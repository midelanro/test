@@ -11,50 +11,66 @@ macro(add_test_executable _executable)
  if(NOT C_ADDITIONAL_FLAGS STREQUAL "")
    set_target_properties(${_executable} PROPERTIES
      COMPILE_FLAGS ${C_ADDITIONAL_FLAGS})
  endif()
  if(WIN32)
    target_link_libraries(${_executable}
      ${ARGN} ${LIBRARY_NAME} ${PCAP_LINK_LIBRARIES})
  else(WIN32)
    target_link_libraries(${_executable}
      ${ARGN} ${LIBRARY_NAME}_static ${PCAP_LINK_LIBRARIES})
  endif(WIN32)
  if(NOT "${LINKER_FLAGS}" STREQUAL "")
    set_target_properties(${_executable} PROPERTIES
      LINK_FLAGS "${LINKER_FLAGS}")
  endif()
  add_dependencies(testprogs ${_executable})
endmacro()

add_test_executable(activatetest)
add_test_executable(can_set_rfmon_test)
add_test_executable(capturetest)
add_test_executable(filtertest)
add_test_executable(findalldevstest)
add_test_executable(findalldevstest-perf)
add_test_executable(opentest)
add_executable(sniffer_report EXCLUDE_FROM_ALL sniffer_report.c ${PROJECT_SOURCE_LIST_WIN32_C})
set_source_files_properties(sniffer_report.c PROPERTIES LANGUAGE CXX)
if(NOT C_ADDITIONAL_FLAGS STREQUAL "")
  set_target_properties(sniffer_report PROPERTIES
    COMPILE_FLAGS ${C_ADDITIONAL_FLAGS})
endif()
if(WIN32)
  target_link_libraries(sniffer_report ${LIBRARY_NAME} ${PCAP_LINK_LIBRARIES})
else(WIN32)
  target_link_libraries(sniffer_report ${LIBRARY_NAME}_static ${PCAP_LINK_LIBRARIES})
endif(WIN32)
if(NOT "${LINKER_FLAGS}" STREQUAL "")
  set_target_properties(sniffer_report PROPERTIES
    LINK_FLAGS "${LINKER_FLAGS}")
endif()
add_dependencies(testprogs sniffer_report)
add_test_executable(reactivatetest)
add_test_executable(versiontest)
add_test_executable(writecaptest)

if(NOT WIN32)
  add_test_executable(selpolltest)
  # Fails to link on Windows:
  # translatetest.obj : error LNK2019: unresolved external symbol
  #   _pcapint_atodn referenced in function _test_pcapint_atodn
  # translatetest.obj : error LNK2019: unresolved external symbol
  #   _pcapint_atoan referenced in function _test_pcapint_atoan
  # translatetest.obj : error LNK2019: unresolved external symbol
  #   _pcapint_xdtoi referenced in function _test_pcapint_xdtoi
  # translatetest.obj : error LNK2019: unresolved external symbol
  #   _pcapint_createsrcstr_ex referenced in function _test_pcapint_parsesrcstr_ex
  # translatetest.obj : error LNK2019: unresolved external symbol
  #   _pcapint_parsesrcstr_ex referenced in function _test_pcapint_parsesrcstr_ex
  add_test_executable(translatetest)
endif()

add_test_executable(threadsignaltest ${CMAKE_THREAD_LIBS_INIT})

# Same as in configure.ac.
if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR
   CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR
