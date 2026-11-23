"""ST10F2xx special function registers (subset) and trap vectors.

Taken from the C167/ST10F269/ST10F275 user manuals from memory: verify against
the datasheet before relying on a name.  Unknown registers are printed as
SFR_xxxx / ESFR_xxxx.
"""

SFR = {
    # CPU core
    0xFE00: "DPP0", 0xFE02: "DPP1", 0xFE04: "DPP2", 0xFE06: "DPP3",
    0xFE08: "CSP", 0xFE0C: "MDH", 0xFE0E: "MDL", 0xFE10: "CP", 0xFE12: "SP",
    0xFE14: "STKOV", 0xFE16: "STKUN",
    0xFE18: "ADDRSEL1", 0xFE1A: "ADDRSEL2", 0xFE1C: "ADDRSEL3", 0xFE1E: "ADDRSEL4",
    0xFF0C: "BUSCON0", 0xFF0E: "MDC", 0xFF10: "PSW", 0xFF12: "SYSCON",
    0xFF14: "BUSCON1", 0xFF16: "BUSCON2", 0xFF18: "BUSCON3", 0xFF1A: "BUSCON4",
    0xFF1C: "ZEROS", 0xFF1E: "ONES", 0xFFAC: "TFR", 0xFEAE: "WDT", 0xFFAE: "WDTCON",
    # ports
    0xFF00: "P0L", 0xFF02: "P0H", 0xFF04: "P1L", 0xFF06: "P1H",
    0xFFC0: "P2", 0xFFC2: "DP2", 0xFFC4: "P3", 0xFFC6: "DP3", 0xFFC8: "P4", 0xFFCA: "DP4",
    0xFFA2: "P5", 0xFFA4: "P5DIDIS", 0xFFCC: "P6", 0xFFCE: "DP6", 0xFFD0: "P7", 0xFFD2: "DP7",
    0xFFD4: "P8", 0xFFD6: "DP8",
    # CAPCOM1/2
    0xFE50: "T0", 0xFE52: "T1", 0xFE54: "T0REL", 0xFE56: "T1REL", 0xFF50: "T01CON",
    0xFF20: "T78CON",
    0xFF52: "CCM0", 0xFF54: "CCM1", 0xFF56: "CCM2", 0xFF58: "CCM3",
    0xFF22: "CCM4", 0xFF24: "CCM5", 0xFF26: "CCM6", 0xFF28: "CCM7",
    # GPT1/2
    0xFE40: "T2", 0xFE42: "T3", 0xFE44: "T4", 0xFE46: "T5", 0xFE48: "T6", 0xFE4A: "CAPREL",
    0xFF40: "T2CON", 0xFF42: "T3CON", 0xFF44: "T4CON", 0xFF46: "T5CON", 0xFF48: "T6CON",
    # ADC
    0xFEA0: "ADDAT", 0xFFA0: "ADCON",
    # ASC0 / SSC
    0xFEB0: "S0TBUF", 0xFEB2: "S0RBUF", 0xFEB4: "S0BG", 0xFFB0: "S0CON", 0xFFB2: "SSCCON",
    # PWM
    0xFE30: "PW0", 0xFE32: "PW1", 0xFE34: "PW2", 0xFE36: "PW3",
    0xFF30: "PWMCON0", 0xFF32: "PWMCON1",
    # interrupt control
    0xFF60: "T2IC", 0xFF62: "T3IC", 0xFF64: "T4IC", 0xFF66: "T5IC", 0xFF68: "T6IC",
    0xFF6A: "CRIC", 0xFF6C: "S0TIC", 0xFF6E: "S0RIC", 0xFF70: "S0EIC",
    0xFF72: "SSCTIC", 0xFF74: "SSCRIC", 0xFF76: "SSCEIC",
    0xFF98: "ADCIC", 0xFF9A: "ADEIC", 0xFF9C: "T0IC", 0xFF9E: "T1IC",
}
for i in range(16):
    SFR[0xFE80 + 2 * i] = f"CC{i}"
    SFR[0xFE60 + 2 * i] = f"CC{16 + i}"
    SFR[0xFF78 + 2 * i] = f"CC{i}IC"

ESFR = {
    0xF050: "T7", 0xF052: "T8", 0xF054: "T7REL", 0xF056: "T8REL",
    0xF0A0: "ADDAT2", 0xF0B0: "SSCTB", 0xF0B2: "SSCRB", 0xF0B4: "SSCBR",
    0xF030: "PT0", 0xF038: "PP0",
    0xF100: "DP0L", 0xF102: "DP0H", 0xF104: "DP1L", 0xF106: "DP1H", 0xF108: "RP0H",
    0xF1C0: "EXICON", 0xF1C2: "ODP2", 0xF1C6: "ODP3", 0xF1CE: "ODP6", 0xF1D2: "ODP7",
    0xF1D6: "ODP8", 0xF07C: "IDCHIP", 0xF024: "XPERCON",
    0xF186: "XP0IC", 0xF18E: "XP1IC", 0xF196: "XP2IC", 0xF19E: "XP3IC",
    0xF17A: "T7IC", 0xF17C: "T8IC", 0xF17E: "PWMIC",
    0xF184: "CC29IC", 0xF18C: "CC30IC", 0xF194: "CC31IC", 0xF19C: "S0TBIC",
}
for _i in range(13):
    ESFR[0xF160 + 2 * _i] = f"CC{16 + _i}IC"

# bit-addressable SFR names are the same as SFR names
BIT_SFR = {}

# trap / interrupt vectors (address -> source), C167 numbering
VECTORS = {
    0x00: "RESET", 0x08: "NMI", 0x10: "STKOF", 0x18: "STKUF", 0x28: "CLASS_B",
    0x80: "T0INT", 0x84: "T1INT", 0x88: "T2INT", 0x8C: "T3INT", 0x90: "T4INT",
    0x94: "T5INT", 0x98: "T6INT", 0x9C: "CRINT", 0xA0: "ADCINT", 0xA4: "ADEINT",
    0xA8: "S0TINT", 0xAC: "S0RINT", 0xB0: "S0EINT", 0xB4: "SSCTINT", 0xB8: "SSCRINT",
    0xBC: "SSCEINT",
}
for i in range(16):
    VECTORS[0x40 + 4 * i] = f"CC{i}INT"
for i in range(13):
    VECTORS[0xC0 + 4 * i] = f"CC{16 + i}INT"
VECTORS.update({0xF4: "T7INT", 0xF8: "T8INT", 0xFC: "PWMINT",
                0x100: "XP0INT", 0x104: "XP1INT", 0x108: "XP2INT", 0x10C: "XP3INT",
                0x110: "CC29INT", 0x114: "CC30INT", 0x118: "CC31INT", 0x11C: "S0TBINT"})
