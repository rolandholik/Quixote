
/* Size of identities. */
#define IDSIZE 32


/* Includes. */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <cmsis_os.h>
#include <rng.h>
#include <rtc.h>
#include <usart.h>
#include <gpio.h>
#include <rtosal.h>

#include "HurdLib.h"
#include <Buffer.h>

#include "cellular_control_api.h"

#include "sancho.h"


/* External variable declarations. */
_Bool UARTend = false;


/* External function definitions. */
extern int __io_putchar(int ch);
extern int __io_getchar(void);
void SystemClock_Config(void);


/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

	/* Initialize hardware and peripherals. */
	HAL_Init();
	SystemClock_Config();


        /* Peripheral initializations. */
	MX_GPIO_Init();
	MX_USART2_UART_Init();
	MX_RTC_Init();
	MX_RNG_Init();
	MX_RTC_Init();


	/* Initialize the worker threads. */
	interpreter_init();


	/* Start the cellular engine. */
	cellular_init();
#if 0
	cellular_start();
#endif


	/* Start thread processing. */
	osKernelStart();

	while ( true )
		continue;

	return 0;
}


int __io_putchar(int output)

{
	HAL_UART_Transmit(&huart2, (uint8_t *) &output, 1, 0xFFFF);

	return output;
}


void Error_Handler(void)
{
#if 0
	BSP_LED_On(LED5);
#endif

  while (1)
	  continue;

}


#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
    ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */

  /* Infinite loop */
  while (1)
  {
  }
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */


 /**
  * @brief  Period elapsed callback in non blocking mode
  * @note   This function is called  when TIM3 interrupt took place, inside
  * HAL_TIM_IRQHandler(). It makes a direct call to HAL_IncTick() to increment
  * a global variable "uwTick" used as application time base.
  * @param  htim : TIM handle
  * @retval None
  */
void HAL_TIM_PeriodElapsedCallback(TIM_HandleTypeDef *htim)
{
	if (htim->Instance == TIM3) {
		HAL_IncTick();
	}

	return;
}


void SystemClock_Config(void)

{
	RCC_OscInitTypeDef RCC_OscInitStruct   = {0};
	RCC_ClkInitTypeDef RCC_ClkInitStruct   = {0};
	RCC_PeriphCLKInitTypeDef PeriphClkInit = {0};

	/** Initializes the RCC Oscillators according to the specified
	 * parameters in the RCC_OscInitTypeDef structure.
	 */
	RCC_OscInitStruct.OscillatorType = \
		RCC_OSCILLATORTYPE_LSI | RCC_OSCILLATORTYPE_MSI;
	RCC_OscInitStruct.LSIState = RCC_LSI_ON;
	RCC_OscInitStruct.MSIState = RCC_MSI_ON;
	RCC_OscInitStruct.MSICalibrationValue = 0;
	RCC_OscInitStruct.MSIClockRange = RCC_MSIRANGE_6;
	RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
	RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_MSI;
	RCC_OscInitStruct.PLL.PLLM = 1;
	RCC_OscInitStruct.PLL.PLLN = 40;
	RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
	RCC_OscInitStruct.PLL.PLLQ = RCC_PLLQ_DIV2;
	RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV2;
	if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
	{
		Error_Handler();
	}


	/* Initialize CPU clocks and buses. */
	RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK   |	\
		RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_PCLK1 |	\
		RCC_CLOCKTYPE_PCLK2;
	RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
	RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
	RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
	RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

	if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_4) != HAL_OK)
	{
		Error_Handler();
	}

	PeriphClkInit.PeriphClockSelection = RCC_PERIPHCLK_RTC | \
		RCC_PERIPHCLK_USART1 | RCC_PERIPHCLK_USART2    | \
		RCC_PERIPHCLK_RNG;
	PeriphClkInit.Usart1ClockSelection = RCC_USART1CLKSOURCE_PCLK2;
	PeriphClkInit.Usart2ClockSelection = RCC_USART2CLKSOURCE_PCLK1;
	PeriphClkInit.RTCClockSelection = RCC_RTCCLKSOURCE_LSI;
	PeriphClkInit.RngClockSelection = RCC_RNGCLKSOURCE_PLLSAI1;
	PeriphClkInit.PLLSAI1.PLLSAI1Source = RCC_PLLSOURCE_MSI;
	PeriphClkInit.PLLSAI1.PLLSAI1M = 1;
	PeriphClkInit.PLLSAI1.PLLSAI1N = 20;
	PeriphClkInit.PLLSAI1.PLLSAI1P = RCC_PLLP_DIV2;
	PeriphClkInit.PLLSAI1.PLLSAI1Q = RCC_PLLQ_DIV2;
	PeriphClkInit.PLLSAI1.PLLSAI1R = RCC_PLLR_DIV2;
	PeriphClkInit.PLLSAI1.PLLSAI1ClockOut = RCC_PLLSAI1_48M2CLK;
	if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInit) != HAL_OK)
	{
		Error_Handler();
	}


	/* Configure voltage regulator. */
	if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1) != \
	    HAL_OK)
	{
		Error_Handler();
	}

	return;
}


