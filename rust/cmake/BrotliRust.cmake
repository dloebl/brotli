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

# Rust target triple(s): explicit, or inferred for common cross builds.
set(_brotli_rust_targets "${BROTLI_RUST_TARGET}")
if (NOT _brotli_rust_targets)
  set(_osx_archs "${CMAKE_OSX_ARCHITECTURES}")
  if (CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(_ios_suffix "")
    if (CMAKE_OSX_SYSROOT MATCHES "[Ss]imulator")
      set(_ios_suffix "-sim")
    endif()
    if (NOT _osx_archs)
      set(_osx_archs arm64)
    endif()
    foreach(a ${_osx_archs})
      if (a STREQUAL "arm64")
        list(APPEND _brotli_rust_targets "aarch64-apple-ios${_ios_suffix}")
      elseif (a STREQUAL "x86_64")
        list(APPEND _brotli_rust_targets "x86_64-apple-ios")
      endif()
    endforeach()
  elseif (APPLE AND _osx_archs)
    foreach(a ${_osx_archs})
      if (a STREQUAL "arm64")
        list(APPEND _brotli_rust_targets aarch64-apple-darwin)
      elseif (a STREQUAL "x86_64")
        list(APPEND _brotli_rust_targets x86_64-apple-darwin)
      endif()
    endforeach()
  elseif (ANDROID)
    if (CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
      set(_brotli_rust_targets aarch64-linux-android)
    elseif (CMAKE_ANDROID_ARCH_ABI STREQUAL "armeabi-v7a")
      set(_brotli_rust_targets armv7-linux-androideabi)
    elseif (CMAKE_ANDROID_ARCH_ABI STREQUAL "x86")
      set(_brotli_rust_targets i686-linux-android)
    elseif (CMAKE_ANDROID_ARCH_ABI STREQUAL "x86_64")
      set(_brotli_rust_targets x86_64-linux-android)
    endif()
  elseif (BROTLI_EMSCRIPTEN)
    set(_brotli_rust_targets wasm32-unknown-emscripten)
  elseif (CMAKE_CROSSCOMPILING OR CMAKE_C_COMPILER_TARGET)
    set(_triple "${CMAKE_C_COMPILER_TARGET}")
    if (NOT _triple)
      get_filename_component(_cc_name "${CMAKE_C_COMPILER}" NAME)
      string(REGEX REPLACE "-(gcc|cc|clang)(-[0-9.]+)?(\\.exe)?$" "" _triple "${_cc_name}")
    endif()
    if (_triple MATCHES "^arm-linux-gnueabihf$")
      set(_brotli_rust_targets armv7-unknown-linux-gnueabihf)
    elseif (_triple MATCHES "^arm-linux-gnueabi$")
      set(_brotli_rust_targets arm-unknown-linux-gnueabi)
    elseif (_triple MATCHES "^([a-z0-9_]+)-(linux-gnu.*)$")
      set(_brotli_rust_targets "${CMAKE_MATCH_1}-unknown-${CMAKE_MATCH_2}")
    elseif (_triple MATCHES "^([a-z0-9_]+)-w64-mingw32$")
      set(_brotli_rust_targets "${CMAKE_MATCH_1}-pc-windows-gnu")
    endif()
  endif()
  if (CMAKE_CROSSCOMPILING AND NOT _brotli_rust_targets)
    message(FATAL_ERROR "Cross-compiling: cannot infer the Rust target triple; "
                        "set BROTLI_RUST_TARGET (e.g. -DBROTLI_RUST_TARGET=aarch64-unknown-linux-gnu)")
  endif()
endif()

set(BROTLI_RUST_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/rust-target")
if (BROTLI_RUST_PROFILE STREQUAL "dev")
  set(_brotli_profile_dir "debug")
else()
  set(_brotli_profile_dir "${BROTLI_RUST_PROFILE}")
endif()
if (MSVC)
  set(_brotli_archive_name "brotli_capi.lib")
else()
  set(_brotli_archive_name "libbrotli_capi.a")
endif()
set(_brotli_cargo_base build --manifest-path "${BROTLI_RUST_DIR}/Cargo.toml" -p brotli-capi
    --profile "${BROTLI_RUST_PROFILE}" --target-dir "${BROTLI_RUST_TARGET_DIR}")
set(_brotli_commands "")
set(_brotli_archives "")
if (NOT _brotli_rust_targets)
  list(APPEND _brotli_commands COMMAND "${BROTLI_CARGO}" ${_brotli_cargo_base})
  list(APPEND _brotli_archives "${BROTLI_RUST_TARGET_DIR}/${_brotli_profile_dir}/${_brotli_archive_name}")
else()
  foreach(t ${_brotli_rust_targets})
    list(APPEND _brotli_commands COMMAND "${BROTLI_CARGO}" ${_brotli_cargo_base} --target "${t}")
    list(APPEND _brotli_archives "${BROTLI_RUST_TARGET_DIR}/${t}/${_brotli_profile_dir}/${_brotli_archive_name}")
  endforeach()
endif()
list(LENGTH _brotli_archives _brotli_num_archives)
if (_brotli_num_archives GREATER 1)
  # Universal (fat) archive for multi-architecture Apple builds.
  set(BROTLI_RUST_ARCHIVE "${BROTLI_RUST_TARGET_DIR}/universal/${_brotli_archive_name}")
  find_program(BROTLI_LIPO lipo)
  list(APPEND _brotli_commands
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${BROTLI_RUST_TARGET_DIR}/universal"
    COMMAND "${BROTLI_LIPO}" -create ${_brotli_archives} -output "${BROTLI_RUST_ARCHIVE}")
else()
  set(BROTLI_RUST_ARCHIVE "${_brotli_archives}")
endif()
if (_brotli_rust_targets)
  message(STATUS "Rust target(s): ${_brotli_rust_targets}")
endif()

# cargo tracks its own dependencies; running it on every build is cheap.
add_custom_target(brotli_rust_archive ALL
  ${_brotli_commands}
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
    # The precompiled Rust `core` carries DWARF; like the C Release build,
    # ship no debug info unless a debug configuration is requested.
    if (NOT MSVC)
      if (APPLE)
        set(_strip_flag "-Wl,-S")
      else()
        set(_strip_flag "-Wl,--strip-debug")
      endif()
      target_link_options(${target} PRIVATE
        "$<$<NOT:$<OR:$<CONFIG:Debug>,$<CONFIG:RelWithDebInfo>>>:${_strip_flag}>")
    endif()
  else()
    # The archive content is replaced by the Rust archive after "building"
    # the placeholder, so that install(TARGETS) etc. work as usual.
    add_library(${target} STATIC "${BROTLI_RUST_DIR}/cmake/empty.c")
    add_custom_command(TARGET ${target} POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E copy "${BROTLI_RUST_ARCHIVE}" "$<TARGET_FILE:${target}>"
      COMMENT "Installing Rust archive as ${lib}")
    if (CMAKE_STRIP AND NOT MSVC)
      # Drop DWARF of the precompiled Rust `core` (see above).
      add_custom_command(TARGET ${target} POST_BUILD
        COMMAND "$<IF:$<OR:$<CONFIG:Debug>,$<CONFIG:RelWithDebInfo>>,${CMAKE_COMMAND};-E;true,${CMAKE_STRIP};-S;$<TARGET_FILE:${target}>>"
        COMMAND_EXPAND_LISTS)
    endif()
  endif()
  add_dependencies(${target} brotli_rust_archive)
endfunction()
