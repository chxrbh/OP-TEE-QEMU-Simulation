project (secure_iiot C)

set (COMMON_SRC host/common.c host/kmm_mock.c host/paillier_host.c)

add_executable (secure_iiot_demo host/main_demo.c ${COMMON_SRC})
add_executable (secure_iiot_bench host/main_bench.c ${COMMON_SRC})
add_executable (secure_iiot_delegate_demo host/main_delegate_demo.c ${COMMON_SRC})
add_executable (secure_iiot_paillier_ta_demo host/main_paillier_ta_demo.c ${COMMON_SRC})
add_executable (secure_iiot_full_crypto_demo host/main_full_crypto_demo.c ${COMMON_SRC})
add_executable (secure_iiot_full_crypto_verify host/main_full_crypto_verify.c ${COMMON_SRC})
add_executable (secure_iiot_full_crypto_bench host/main_full_crypto_bench.c ${COMMON_SRC})
add_executable (${PROJECT_NAME} host/main_demo.c ${COMMON_SRC})
add_executable (secure_iiot_paillier_ref host/main_paillier_ref.c host/paillier_host.c)
add_executable (secure_iiot_paillier_bench host/main_paillier_bench.c host/paillier_host.c)

set (TEEC_TARGETS
	secure_iiot_demo
	secure_iiot_bench
	secure_iiot_delegate_demo
	secure_iiot_paillier_ta_demo
	secure_iiot_full_crypto_demo
	secure_iiot_full_crypto_verify
	secure_iiot_full_crypto_bench
	${PROJECT_NAME})

set (CRYPTO_ONLY_TARGETS
	secure_iiot_paillier_ref
	secure_iiot_paillier_bench)

foreach (target ${TEEC_TARGETS} ${CRYPTO_ONLY_TARGETS})
	target_include_directories(${target}
				   PRIVATE ta/include
				   PRIVATE include
				   PRIVATE host)
endforeach()

foreach (target ${TEEC_TARGETS})
	target_link_libraries (${target} PRIVATE teec crypto)
endforeach()

foreach (target ${CRYPTO_ONLY_TARGETS})
	target_link_libraries (${target} PRIVATE crypto)
endforeach()

install (TARGETS ${TEEC_TARGETS} ${CRYPTO_ONLY_TARGETS}
	 DESTINATION ${CMAKE_INSTALL_BINDIR})
