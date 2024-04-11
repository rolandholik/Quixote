/* Includes */
#include <stm32l5xx_hal.h>

void NAAAIM_TTYduct_interrupt_handler(UART_HandleTypeDef *uart);


void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart)

{
	NAAAIM_TTYduct_interrupt_handler(huart);
	return;
}
