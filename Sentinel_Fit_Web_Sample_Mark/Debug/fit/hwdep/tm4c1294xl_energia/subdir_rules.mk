################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Each subdirectory must supply rules for building sources it contributes
fit/hwdep/tm4c1294xl_energia/%.o: ../fit/hwdep/tm4c1294xl_energia/%.c $(GEN_OPTS) $(GEN_HDRS)
	@echo 'Building file: $<'
	@echo 'Invoking: GNU Compiler'
	"C:/ti/ccsv6/tools/compiler/gcc-arm-none-eabi-4_9-2015q3/bin/arm-none-eabi-gcc.exe" -c -mcpu=cortex-m4 -march=armv7e-m -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -fno-exceptions -DPART_TM4C1294NCPDT -DF_CPU=120000000L -DARDUINO=101 -DENERGIA=13 -D__GNU_VISIBLE -I"C:/Users/Gemalto/DEVELOPMENT/CCS_Workspaces/workspace_clp/core_lib_energia/inc" -I"C:/Users/Gemalto/git/Sentinel_Fit_Web_Sample_Mark/Sentinel_Fit_Web_Sample_Mark/fit/inc" -I"C:/Users/Gemalto/DEVELOPMENT/CCS_Workspaces/workspace_clp/ethernet_lib_energia/inc" -I"C:/Users/Gemalto/git/Sentinel_Fit_Web_Sample_Mark/Sentinel_Fit_Web_Sample_Mark" -I"C:/ti/ccsv6/tools/compiler/gcc-arm-none-eabi-4_9-2015q3/arm-none-eabi/include" -I"C:/Users/Gemalto/git/Sentinel_Fit_Web_Sample_Mark/Sentinel_Fit_Web_Sample_Mark/fit/mbedtls-2.2.1/include" -O0 -ffunction-sections -fdata-sections -fsingle-precision-constant -g -gdwarf-3 -gstrict-dwarf -Wall -specs="nosys.specs" -MD -std=c99 -c -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" $(GEN_OPTS__FLAG) "$<"
	@echo 'Finished building: $<'
	@echo ' '

fit/hwdep/tm4c1294xl_energia/%.o: ../fit/hwdep/tm4c1294xl_energia/%.cpp $(GEN_OPTS) $(GEN_HDRS)
	@echo 'Building file: $<'
	@echo 'Invoking: GNU Compiler'
	"C:/ti/ccsv6/tools/compiler/gcc-arm-none-eabi-4_9-2015q3/bin/arm-none-eabi-gcc.exe" -c -mcpu=cortex-m4 -march=armv7e-m -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -fno-exceptions -DPART_TM4C1294NCPDT -DF_CPU=120000000L -DARDUINO=101 -DENERGIA=13 -D__GNU_VISIBLE -I"C:/Users/Gemalto/DEVELOPMENT/CCS_Workspaces/workspace_clp/core_lib_energia/inc" -I"C:/Users/Gemalto/git/Sentinel_Fit_Web_Sample_Mark/Sentinel_Fit_Web_Sample_Mark/fit/inc" -I"C:/Users/Gemalto/DEVELOPMENT/CCS_Workspaces/workspace_clp/ethernet_lib_energia/inc" -I"C:/Users/Gemalto/git/Sentinel_Fit_Web_Sample_Mark/Sentinel_Fit_Web_Sample_Mark" -I"C:/ti/ccsv6/tools/compiler/gcc-arm-none-eabi-4_9-2015q3/arm-none-eabi/include" -I"C:/Users/Gemalto/git/Sentinel_Fit_Web_Sample_Mark/Sentinel_Fit_Web_Sample_Mark/fit/mbedtls-2.2.1/include" -O0 -ffunction-sections -fdata-sections -fsingle-precision-constant -g -gdwarf-3 -gstrict-dwarf -Wall -specs="nosys.specs" -MD -std=c99 -c -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -fno-rtti -o"$@" $(GEN_OPTS__FLAG) "$<"
	@echo 'Finished building: $<'
	@echo ' '


