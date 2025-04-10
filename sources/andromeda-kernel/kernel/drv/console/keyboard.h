#pragma once

#include <stdint.h>

#define K(category, value) (((category) << 8) | (value))
#define KCAT(x) (((x) >> 8) & 0x0f)
#define KVAL(x) ((x) & 0xff)

#define KC_LETTER 1
#define KC_DIGIT 2
#define KC_SYMBOL 3
#define KC_NUMPAD 4
#define KC_ARROW 5
#define KC_FUNCTION 6
#define KC_CONTROL 7

#define K_A K(KC_LETTER, 0)
#define K_B K(KC_LETTER, 1)
#define K_C K(KC_LETTER, 2)
#define K_D K(KC_LETTER, 3)
#define K_E K(KC_LETTER, 4)
#define K_F K(KC_LETTER, 5)
#define K_G K(KC_LETTER, 6)
#define K_H K(KC_LETTER, 7)
#define K_I K(KC_LETTER, 8)
#define K_J K(KC_LETTER, 9)
#define K_K K(KC_LETTER, 10)
#define K_L K(KC_LETTER, 11)
#define K_M K(KC_LETTER, 12)
#define K_N K(KC_LETTER, 13)
#define K_O K(KC_LETTER, 14)
#define K_P K(KC_LETTER, 15)
#define K_Q K(KC_LETTER, 16)
#define K_R K(KC_LETTER, 17)
#define K_S K(KC_LETTER, 18)
#define K_T K(KC_LETTER, 19)
#define K_U K(KC_LETTER, 20)
#define K_V K(KC_LETTER, 21)
#define K_W K(KC_LETTER, 22)
#define K_X K(KC_LETTER, 23)
#define K_Y K(KC_LETTER, 24)
#define K_Z K(KC_LETTER, 25)

#define K_0 K(KC_DIGIT, 0)
#define K_1 K(KC_DIGIT, 1)
#define K_2 K(KC_DIGIT, 2)
#define K_3 K(KC_DIGIT, 3)
#define K_4 K(KC_DIGIT, 4)
#define K_5 K(KC_DIGIT, 5)
#define K_6 K(KC_DIGIT, 6)
#define K_7 K(KC_DIGIT, 7)
#define K_8 K(KC_DIGIT, 8)
#define K_9 K(KC_DIGIT, 9)

#define K_SPACE K(KC_SYMBOL, 0)
#define K_APOSTROPHE K(KC_SYMBOL, 1)
#define K_COMMA K(KC_SYMBOL, 2)
#define K_MINUS K(KC_SYMBOL, 3)
#define K_DOT K(KC_SYMBOL, 4)
#define K_SLASH K(KC_SYMBOL, 5)
#define K_SEMICOLON K(KC_SYMBOL, 6)
#define K_EQUALS K(KC_SYMBOL, 7)
#define K_LEFT_BRACKET K(KC_SYMBOL, 8)
#define K_BACKSLASH K(KC_SYMBOL, 9)
#define K_RIGHT_BRACKET K(KC_SYMBOL, 10)
#define K_GRAVE K(KC_SYMBOL, 11)

#define K_NUM_0 K(KC_NUMPAD, 0)
#define K_NUM_1 K(KC_NUMPAD, 1)
#define K_NUM_2 K(KC_NUMPAD, 2)
#define K_NUM_3 K(KC_NUMPAD, 3)
#define K_NUM_4 K(KC_NUMPAD, 4)
#define K_NUM_5 K(KC_NUMPAD, 5)
#define K_NUM_6 K(KC_NUMPAD, 6)
#define K_NUM_7 K(KC_NUMPAD, 7)
#define K_NUM_8 K(KC_NUMPAD, 8)
#define K_NUM_9 K(KC_NUMPAD, 9)
#define K_NUM_DOT K(KC_NUMPAD, 10)
#define K_NUM_ENTER K(KC_NUMPAD, 11)
#define K_NUM_STAR K(KC_NUMPAD, 12)
#define K_NUM_PLUS K(KC_NUMPAD, 13)
#define K_NUM_MINUS K(KC_NUMPAD, 14)
#define K_NUM_SLASH K(KC_NUMPAD, 15)

#define K_UP K(KC_ARROW, 0)
#define K_DOWN K(KC_ARROW, 1)
#define K_RIGHT K(KC_ARROW, 2)
#define K_LEFT K(KC_ARROW, 3)

#define K_F1 K(KC_FUNCTION, 0)
#define K_F2 K(KC_FUNCTION, 1)
#define K_F3 K(KC_FUNCTION, 2)
#define K_F4 K(KC_FUNCTION, 3)
#define K_F5 K(KC_FUNCTION, 4)
#define K_F6 K(KC_FUNCTION, 5)
#define K_F7 K(KC_FUNCTION, 6)
#define K_F8 K(KC_FUNCTION, 7)
#define K_F9 K(KC_FUNCTION, 8)
#define K_F10 K(KC_FUNCTION, 9)
#define K_F11 K(KC_FUNCTION, 10)
#define K_F12 K(KC_FUNCTION, 11)

#define K_ESCAPE K(KC_CONTROL, 0)
#define K_PRINT K(KC_CONTROL, 1)
#define K_PAUSE K(KC_CONTROL, 2)
#define K_INSERT K(KC_CONTROL, 3)
#define K_DELETE K(KC_CONTROL, 4)
#define K_BACKSPACE K(KC_CONTROL, 5)
#define K_HOME K(KC_CONTROL, 6)
#define K_END K(KC_CONTROL, 7)
#define K_PAGE_UP K(KC_CONTROL, 8)
#define K_PAGE_DOWN K(KC_CONTROL, 9)
#define K_TAB K(KC_CONTROL, 10)
#define K_ENTER K(KC_CONTROL, 11)

#define KF_CONTROL 0x1000
#define KF_SHIFT 0x2000
#define KF_ALT 0x4000
#define KF_NUM_LOCK 0x8000

uint16_t keyboard_read();
