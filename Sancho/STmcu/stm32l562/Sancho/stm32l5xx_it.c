/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    GPIO/GPIO_IOToggle/Src/stm32l5xx_it.c
  * @author  MCD Application Team
  * @brief   Main Interrupt Service Routines.
  *          This file provides template for all exceptions handler and
  *          peripherals interrupt service routine.
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2019 STMicroelectronics.
  * All rights reserved.</center></h2>
  *
  * This software component is licensed by ST under BSD 3-Clause license,
  * the "License"; You may not use this file except in compliance with the
  * License. You may obtain a copy of the License at:
  *                        opensource.org/licenses/BSD-3-Clause
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include <stdio.h>

#include "main.h"
#include "stm32l5xx_it.h"
/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN TD */

/* USER CODE END TD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/* External variables --------------------------------------------------------*/

/* USER CODE BEGIN EV */

/* USER CODE END EV */

/******************************************************************************/
/*           Cortex Processor Interruption and Exception Handlers          */
/******************************************************************************/
/**
  * @brief This function handles Non maskable interrupt.
  */
void NMI_Handler(void)
{
	printf("* NMI handler. *\n");
}


/**
  * @brief This function handles Hard fault interrupt.
  */
void HardFault_Handler(void)
{
	printf("* HardFault. *\n");

	while ( 1 )
		continue;
}


/**
  * @brief This function handles Memory management fault.
  */
void MemManage_Handler(void)
{
	printf("*Memory management. *\n");

	while ( 1 )
		continue;
}

/**
  * @brief This function handles Prefetch fault, memory access fault.
  */
void BusFault_Handler(void)
{
	printf("* Bus fault. *\n");

	while ( 1 )
		continue;
}


/**
  * @brief This function handles Undefined instruction or illegal state.
  */
void UsageFault_Handler(void)

{
	printf("* Usage fault. *\n");

	while ( 1 )
		continue;

}


/**
  * @brief This function handles System service call via SWI instruction.
  */
void SVC_Handler(void)

{
	printf("* SVC handler. *\n");
}


/**
  * @brief This function handles Debug monitor.
  */
void DebugMon_Handler(void)
{
	printf("* Debugmon handler. *\n");
}


/**
  * @brief This function handles Pendable request for system service.
  */
void PendSV_Handler(void)
{
	printf("* PendSV handler. *\n");
}


/**
  * @brief This function handles System tick timer.
  */
void SysTick_Handler(void)
{
	HAL_IncTick();
}



/**
 * External function call.
 *
 * This function vectors the USART1 interrupt vector to the HAL
 *
 * for each character that is received.
 *
 * \param uart	A pointer to the structure defining the UART from which
 *		the character is to be received.
 *
 * \return	No return value is defined.
 */

