
/* Size of identities. */
#define IDSIZE 32


/* Includes. */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <HurdLib.h>
#include <Buffer.h>

#include "main.h"
#include "TTYduct.h"
#include "sancho.h"


/* Variables static to this module. */
static TTYduct Duct;

static _Bool Have_Error = false;

extern int __io_putchar(int ch);
extern int __io_getchar(void);


/**
 * @brief System Clock Configuration
 * @retval None
 */
void SystemClock_Config(void)
{
	RCC_OscInitTypeDef RCC_OscInitStruct = {0};
	RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};


	/* Configure voltage regulator. */
	if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE0) \
	    != HAL_OK) {
		Error_Handler();
	}


	/* Initialize bus oscillators. */
	RCC_OscInitStruct.OscillatorType      = RCC_OSCILLATORTYPE_MSI;
	RCC_OscInitStruct.MSIState	      = RCC_MSI_ON;
	RCC_OscInitStruct.MSICalibrationValue = RCC_MSICALIBRATION_DEFAULT;
	RCC_OscInitStruct.MSIClockRange	      = RCC_MSIRANGE_6;
	RCC_OscInitStruct.PLL.PLLState	      = RCC_PLL_ON;
	RCC_OscInitStruct.PLL.PLLSource	      = RCC_PLLSOURCE_MSI;
	RCC_OscInitStruct.PLL.PLLM	      = 1;
	RCC_OscInitStruct.PLL.PLLN	      = 55;
	RCC_OscInitStruct.PLL.PLLP	      = RCC_PLLP_DIV7;
	RCC_OscInitStruct.PLL.PLLQ	      = RCC_PLLQ_DIV2;
	RCC_OscInitStruct.PLL.PLLR	      = RCC_PLLR_DIV2;

	if ( HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK )
		Error_Handler();


	/* Initialize bus clocks. */
	RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK   | \
		RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_PCLK1 | \
		RCC_CLOCKTYPE_PCLK2;
	RCC_ClkInitStruct.SYSCLKSource   = RCC_SYSCLKSOURCE_PLLCLK;
	RCC_ClkInitStruct.AHBCLKDivider	 = RCC_SYSCLK_DIV1;
	RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
	RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

	if ( HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) \
	     != HAL_OK)
		Error_Handler();
}


static void MX_GPIO_Init(void)

{
	__HAL_RCC_GPIOA_CLK_ENABLE();
	return;
}


void HAL_Delay(__IO uint32_t Delay)
{
	while (Delay) {
		if (SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk)
			Delay--;
	}

	return;
}


int main(void)
{
	TTYduct duct = NULL;


	/* Initialize hardware and peripherals. */
	HAL_Init();
	SystemClock_Config();
	MX_GPIO_Init();


	/* Invoke the interpreter for each connection event. */
	INIT(NAAAIM, TTYduct, duct, ERR(goto done));

	while ( true ) {
		if ( !duct->init_device(duct, NULL) )
			ERR(goto done);

#if 0
		printf("%s: Calling interpreter.\r\n", __func__);
		fflush(stdout);
#endif

		sancho_interpreter(duct);
	}


 done:
	printf("%s: Error condition.\n", __func__);

	while ( true )
		continue;
}



void Error_Handler(void)
{
#if 0
	BSP_LED_On(LED5);
#endif

  while (1)
	  continue;

}

void Error(const char *file, const char *function, int line)

{
	char bufr[80];

	Buffer msg = NULL;


	if ( Have_Error )
		return;

	memset(bufr, '\0', sizeof(bufr));
	snprintf(bufr, sizeof(bufr), "T[%s,%s,%d]: Error location.", file, \
		 function, line);

	INIT(HurdLib, Buffer, msg, return);
	msg->add(msg, (unsigned char *) bufr, strlen(bufr) + 1);
	Duct->send_Buffer(Duct, msg);

	Have_Error = true;
	WHACK(msg);
	return;


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

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
