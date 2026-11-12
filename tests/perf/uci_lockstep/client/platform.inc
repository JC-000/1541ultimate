; platform.inc -- where the game state lives in C64 memory.
;
; The program runs with BASIC and KERNAL banked out ($01 = $35) and never
; returns to BASIC, so BASIC's and the KERNAL's zero page is ours. Map:
;   $00-$01   6510 I/O port
;   $02-$1F   program zero page (frame counter, joystick, temps)
;   $20-$5F   game state zero page (CORE_ZP, 64 bytes)
;   $60-$FF   free
;   $0100     stack
;   $0200-$03FF left alone
;   $0400     screen RAM
;   $0801-    program (BASIC SYS stub, code, data)
;   $8000-$82FF game state RAM (CORE_RAM, 768 bytes)
;   $C000-$CFFF left alone

CORE_ZP         = $20
CORE_ZP_SIZE    = $40
CORE_RAM        = $8000
CORE_RAM_SIZE   = $0300
