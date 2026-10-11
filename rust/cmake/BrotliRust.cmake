# Builds libbrotlicommon / libbrotlidec / libbrotlienc from the Rust
# implementation (rust/), keeping the exact library names, SONAMEs, exported
# symbols and headers of the C build.
#
# The Rust code is compiled once into a self-contained, `no_std` static
# archive (rust/capi, depends only on libc + libm).  From it:
#   * SHARED libraries are linked with an explicit export list per library
#     (the same symbols the C build exports), unused code is dead-stripped;
#   * STATIC libraries are copies of the archive (archive members are only
#     pulled in when needed, so linking any combination of the three works).
#
# Variables:
#   BROTLI_CARGO           cargo executable (auto-detected)
#   BROTLI_RUST_TARGET     Rust target triple (default: host; set it when
#                          cross-compiling)
#   BROTLI_RUST_PROFILE    cargo profile (default: release)
#   BROTLI_BUILD_ENC_EXTRA_API  also export BrotliEncoderEstimatePeakMemoryUsage
#                          and BrotliEncoderGetPreparedDictionarySize from the
#                          shared libbrotlienc (same as the C build option)

set(BROTLI_RUST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/rust")

if (NOT BROTLI_CARGO)
  find_program(BROTLI_CARGO cargo HINTS "$ENV{CARGO_HOME}/bin" "$ENV{HOME}/.cargo/bin")
endif()
if (NOT BROTLI_CARGO)
  message(FATAL_ERROR "cargo not found: install a Rust toolchain (https://rustup.rs) "
                      "or configure with -DBROTLI_USE_RUST=OFF to build the C implementation")
endif()
set(BROTLI_RUST_PROFILE "release" CACHE STRING "cargo profile used to build the Rust library")
set(BROTLI_RUST_TARGET "" CACHE STRING "Rust target triple (empty: host)")
mark_as_advanced(BROTLI_CARGO BROTLI_RUST_PROFILE BROTLI_RUST_TARGET)

set(BROTLI_RUST_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/rust-target")
set(_brotli_cargo_args build --manifest-path "${BROTLI_RUST_DIR}/Cargo.toml" -p brotli-capi
    --profile "${BROTLI_RUST_PROFILE}" --target-dir "${BROTLI_RUST_TARGET_DIR}")
set(_brotli_rust_out "${BROTLI_RUST_TARGET_DIR}")
if (BROTLI_RUST_TARGET)
  list(APPEND _brotli_cargo_args --target "${BROTLI_RUST_TARGET}")
  set(_brotli_rust_out "${_brotli_rust_out}/${BROTLI_RUST_TARGET}")
endif()
if (BROTLI_RUST_PROFILE STREQUAL "dev")
  set(_brotli_rust_out "${_brotli_rust_out}/debug")
else()
  set(_brotli_rust_out "${_brotli_rust_out}/${BROTLI_RUST_PROFILE}")
endif()
if (MSVC)
  set(BROTLI_RUST_ARCHIVE "${_brotli_rust_out}/brotli_capi.lib")
else()
  set(BROTLI_RUST_ARCHIVE "${_brotli_rust_out}/libbrotli_capi.a")
endif()

# cargo tracks its own dependencies; running it on every build is cheap.
add_custom_target(brotli_rust_archive ALL
  COMMAND "${BROTLI_CARGO}" ${_brotli_cargo_args}
  BYPRODUCTS "${BROTLI_RUST_ARCHIVE}"
  WORKING_DIRECTORY "${BROTLI_RUST_DIR}"
  COMMENT "Building the Rust brotli implementation (cargo)"
  USES_TERMINAL)

# Export lists.
set(_brotli_export_dir "${CMAKE_CURRENT_BINARY_DIR}/rust-exports")
file(MAKE_DIRECTORY "${_brotli_export_dir}")
function(brotli_rust_export_file lib out_var)
  file(STRINGS "${BROTLI_RUST_DIR}/cmake/${lib}.sym" _syms)
  if (lib STREQUAL "brotlienc" AND BROTLI_BUILD_ENC_EXTRA_API)
    file(STRINGS "${BROTLI_RUST_DIR}/cmake/brotlienc_extra.sym" _extra)
    list(APPEND _syms ${_extra})
  endif()
  if (APPLE)
    set(_file "${_brotli_export_dir}/${lib}.exp")
    set(_text "")
    foreach(s ${_syms})
      string(APPEND _text "_${s}\n")
    endforeach()
  elseif (WIN32)
    set(_file "${_brotli_export_dir}/${lib}.def")
    set(_text "EXPORTS\n")
    foreach(s ${_syms})
      if (s MATCHES "^_k")
        string(APPEND _text "  ${s} DATA\n")
      else()
        string(APPEND _text "  ${s}\n")
      endif()
    endforeach()
  else()
    set(_file "${_brotli_export_dir}/${lib}.map")
    set(_text "{\n  global:\n")
    foreach(s ${_syms})
      string(APPEND _text "    ${s};\n")
    endforeach()
    string(APPEND _text "  local:\n    *;\n};\n")
  endif()
  file(WRITE "${_file}" "${_text}")
  set(${out_var} "${_file}" PARENT_SCOPE)
endfunction()

# Re-link / re-archive whenever the Rust archive changes.
set_source_files_properties("${BROTLI_RUST_DIR}/cmake/empty.c" PROPERTIES
  OBJECT_DEPENDS "${BROTLI_RUST_ARCHIVE}")

# brotli_add_rust_library(<target> <SHARED|STATIC> <lib>)
#   <lib> is brotlicommon / brotlidec / brotlienc (selects the export list).
function(brotli_add_rust_library target type lib)
  if (type STREQUAL "SHARED")
    brotli_rust_export_file(${lib} _exports)
    if (WIN32)
      add_library(${target} SHARED "${BROTLI_RUST_DIR}/cmake/empty.c" "${_exports}")
      # Private link items; set directly so that the plain
      # target_link_libraries() signature can still be used on the target.
      set_property(TARGET ${target} APPEND PROPERTY LINK_LIBRARIES "${BROTLI_RUST_ARCHIVE}")
    elseif (APPLE)
      add_library(${target} SHARED "${BROTLI_RUST_DIR}/cmake/empty.c")
      set_property(TARGET ${target} APPEND PROPERTY LINK_LIBRARIES
        "-Wl,-force_load,${BROTLI_RUST_ARCHIVE}"
        "-Wl,-exported_symbols_list,${_exports}"
        "-Wl,-dead_strip")
      set_property(TARGET ${target} APPEND PROPERTY LINK_DEPENDS "${_exports}")
    else()
      add_library(${target} SHARED "${BROTLI_RUST_DIR}/cmake/empty.c")
      set_property(TARGET ${target} APPEND PROPERTY LINK_LIBRARIES
        "-Wl,--whole-archive" "${BROTLI_RUST_ARCHIVE}" "-Wl,--no-whole-archive"
        "-Wl,--version-script=${_exports}"
        "-Wl,--gc-sections")
      set_property(TARGET ${target} APPEND PROPERTY LINK_DEPENDS "${_exports}")
    endif()
    set_property(TARGET ${target} APPEND PROPERTY LINK_DEPENDS "${BROTLI_RUST_ARCHIVE}")
  else()
    # The archive content is replaced by the Rust archive after "building"
    # the placeholder, so that install(TARGETS) etc. work as usual.
    add_library(${target} STATIC "${BROTLI_RUST_DIR}/cmake/empty.c")
    add_custom_command(TARGET ${target} POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E copy "${BROTLI_RUST_ARCHIVE}" "$<TARGET_FILE:${target}>"
      COMMENT "Installing Rust archive as ${lib}")
  endif()
  add_dependencies(${target} brotli_rust_archive)
endfunction()
