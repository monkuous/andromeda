#include "keyboard.h"
#include "init/bios.h"
#include "util/print.h"

static uint16_t process_rs_oc(unsigned key, uint8_t ascii, uint8_t regular, uint8_t shift) {
    if (ascii != regular) {
        if (ascii == shift) key |= KF_SHIFT;
        else key |= KF_CONTROL;
    }
    return key;
}

static uint16_t process_rs_oa(unsigned key, uint8_t ascii, uint8_t regular, uint8_t shift) {
    if (ascii != regular) {
        if (ascii == shift) key |= KF_SHIFT;
        else key |= KF_ALT;
    }
    return key;
}

static uint16_t process_rsc_oa(unsigned key, uint8_t ascii, uint8_t regular, uint8_t shift, uint8_t control) {
    if (ascii != regular) {
        if (ascii == shift) key |= KF_SHIFT;
        else if (ascii == control) key |= KF_CONTROL;
        else key |= KF_ALT;
    }
    return key;
}

static uint16_t process_digit(int value, uint8_t ascii) {
    static uint8_t shifts[10] = ")!@#$%^&*(";
    return process_rs_oc(K(KC_DIGIT, value), ascii, '0' + value, shifts[value]);
}

static uint16_t process_letter(int offset, uint8_t ascii) {
    static uint8_t chars[26] = "qwertyuiopasdfghjklzxcvbnm";
    return process_rsc_oa(
            K(KC_LETTER, chars[offset] - 'a'),
            ascii,
            chars[offset],
            chars[offset] - 0x20,
            chars[offset] & ~0x60
    );
}

static uint16_t convert_key(uint8_t scancode, uint8_t ascii) {
    switch (scancode) {
    case 0x01: return K_ESCAPE;
    case 0x02: return process_digit(1, ascii);
    case 0x03: return process_rsc_oa(K_2, ascii, '2', '@', 0);
    case 0x04 ... 0x06: return process_digit(scancode - 0x02 + 1, ascii);
    case 0x07: return process_rsc_oa(K_6, ascii, '6', '^', 0x1e);
    case 0x08 ... 0x0a: return process_digit(scancode - 0x02 + 1, ascii);
    case 0x0b: return process_digit(0, ascii);
    case 0x0c: return process_rsc_oa(K_MINUS, ascii, '-', '_', 0x1f);
    case 0x0d: return process_rs_oc(K_EQUALS, ascii, '=', '+');
    case 0x0e: return process_rsc_oa(K_BACKSPACE, ascii, '\b', '\b', 0x7f);
    case 0x0f: return process_rs_oc(K_TAB, ascii, '\t', 0);
    case 0x10 ... 0x19: return process_letter(scancode - 0x10, ascii);
    case 0x1a: return process_rsc_oa(K_LEFT_BRACKET, ascii, '[', '{', 0x1b);
    case 0x1b: return process_rsc_oa(K_RIGHT_BRACKET, ascii, ']', '}', 0x1d);
    case 0x1c: return process_rsc_oa(K_ENTER, ascii, '\r', '\r', '\n');
    case 0x1e ... 0x26: return process_letter(scancode - 4 - 0x10, ascii);
    case 0x27: return process_rs_oa(K_SEMICOLON, ascii, ';', ':');
    case 0x28: return process_rs_oa(K_APOSTROPHE, ascii, '\'', '"');
    case 0x29: return process_rs_oa(K_GRAVE, ascii, '`', '~');
    case 0x2b: return process_rsc_oa(K_BACKSLASH, ascii, '\\', '|', 0x1c);
    case 0x2c ... 0x32: return process_letter(scancode - 9 - 0x10, ascii);
    case 0x33: return process_rs_oa(K_COMMA, ascii, ',', '<');
    case 0x34: return process_rs_oa(K_DOT, ascii, '.', '>');
    case 0x35: return process_rs_oa(K_SLASH, ascii, '/', '?');
    case 0x37: return process_rs_oa(K_NUM_STAR, ascii, '*', '*');
    case 0x39: return K_SPACE;
    case 0x3b ... 0x44: return K(KC_FUNCTION, scancode - 0x3b);
    case 0x47: return ascii ? K_NUM_7 | KF_NUM_LOCK : K_HOME;
    case 0x48: return ascii ? K_NUM_8 | KF_NUM_LOCK : K_UP;
    case 0x49: return ascii ? K_NUM_9 | KF_NUM_LOCK : K_PAGE_UP;
    case 0x4a: return K_NUM_MINUS | (ascii ? 0 : KF_ALT);
    case 0x4b: return ascii ? K_NUM_4 | KF_NUM_LOCK : K_LEFT;
    case 0x4c: return K_NUM_5 | (ascii ? KF_NUM_LOCK : 0);
    case 0x4d: return ascii ? K_NUM_6 | KF_NUM_LOCK : K_RIGHT;
    case 0x4e: return K_NUM_PLUS | (ascii ? 0 : KF_ALT);
    case 0x4f: return ascii ? K_NUM_1 | KF_NUM_LOCK : K_END;
    case 0x50: return ascii ? K_NUM_2 | KF_NUM_LOCK : K_DOWN;
    case 0x51: return ascii ? K_NUM_3 | KF_NUM_LOCK : K_PAGE_DOWN;
    case 0x52: return ascii ? K_NUM_0 | KF_NUM_LOCK : K_INSERT;
    case 0x53: return ascii ? K_NUM_DOT | KF_NUM_LOCK : K_DELETE;
    case 0x54 ... 0x5d: return K(KC_FUNCTION, scancode - 0x54) | KF_SHIFT;
    case 0x5e ... 0x67: return K(KC_FUNCTION, scancode - 0x5e) | KF_CONTROL;
    case 0x68 ... 0x71: return K(KC_FUNCTION, scancode - 0x68) | KF_ALT;
    case 0x72: return K_PRINT | KF_CONTROL;
    case 0x73: return K_LEFT | KF_CONTROL;
    case 0x74: return K_RIGHT | KF_CONTROL;
    case 0x75: return K_END | KF_CONTROL;
    case 0x76: return K_PAGE_DOWN | KF_CONTROL;
    case 0x77: return K_HOME | KF_CONTROL;
    case 0x78 ... 0x80: return K(KC_DIGIT, scancode - 0x78 + 1) | KF_ALT;
    case 0x81: return K_0 | KF_ALT;
    case 0x82: return K_MINUS | KF_ALT;
    case 0x83: return K_EQUALS | KF_ALT;
    case 0x84: return K_PAGE_UP | KF_CONTROL;
    case 0x85: return K_F11;
    case 0x86: return K_F12;
    case 0x87: return K_F11 | KF_SHIFT;
    case 0x88: return K_F12 | KF_SHIFT;
    case 0x89: return K_F11 | KF_CONTROL;
    case 0x8a: return K_F12 | KF_CONTROL;
    case 0x8b: return K_F11 | KF_ALT;
    case 0x8c: return K_F12 | KF_ALT;
    case 0x8d: return K_UP | KF_CONTROL;
    case 0x8e: return K_NUM_MINUS | KF_CONTROL;
    case 0x8f: return K_NUM_5 | KF_CONTROL;
    case 0x90: return K_NUM_PLUS | KF_CONTROL;
    case 0x91: return K_DOWN | KF_CONTROL;
    case 0x92: return K_INSERT | KF_CONTROL;
    case 0x93: return K_DELETE | KF_CONTROL;
    case 0x94: return K_TAB | KF_CONTROL;
    case 0x95: return K_NUM_SLASH | KF_CONTROL;
    case 0x96: return K_NUM_STAR | KF_CONTROL;
    case 0x97: return K_HOME | KF_ALT;
    case 0x98: return K_UP | KF_ALT;
    case 0x99: return K_PAGE_UP | KF_ALT;
    case 0x9b: return K_LEFT | KF_ALT;
    case 0x9d: return K_RIGHT | KF_ALT;
    case 0x9f: return K_END | KF_ALT;
    case 0xa0: return K_DOWN | KF_ALT;
    case 0xa1: return K_PAGE_DOWN | KF_ALT;
    case 0xa2: return K_INSERT | KF_ALT;
    case 0xa3: return K_DELETE | KF_ALT;
    case 0xa4: return K_NUM_SLASH | KF_ALT;
    case 0xa5: return K_TAB | KF_ALT;
    case 0xa6: return K_ENTER | KF_ALT;
    default: printk("keyboard: unknown scancode: 0x%2x\n", scancode); return 0;
    }
}

uint16_t keyboard_read() {
    regs_t regs = {.eax = 0x100};
    intcall(0x16, &regs);
    if (regs.eflags & 0x40) return 0;

    regs = (regs_t){};
    intcall(0x16, &regs);
    return convert_key(regs.eax >> 8, regs.eax);
}
