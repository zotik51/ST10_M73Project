#!/usr/bin/env python3
"""ST10 / C166 recursive-descent disassembler for the Январь 7.3 (M73) image.

Features
  * full C166 base instruction set (+ MAC opcode slots shown as raw "co*")
  * recursive descent from the reset / interrupt vectors and the app vector
    table at 0x4000, plus extra entry points given on the command line
  * data-page tracking: MOV DPPx,#imm, EXTP/EXTS (#imm and Rw forms when the
    Rw value is known from a preceding MOV Rw,#imm), EXTR for ESFR access
  * resolved physical addresses are annotated with SFR names and with
    calibration names from maps/calibrations.csv
  * writes an .asm listing, a function list and a calibration xref table

usage: st10dis.py firmware/ST10.bin maps/calibrations.csv out/
"""
import collections
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from st10_sfr import SFR, ESFR, BIT_SFR, VECTORS  # noqa: E402

CC = ["cc_UC", "cc_NET", "cc_Z", "cc_NZ", "cc_V", "cc_NV", "cc_N", "cc_NN",
      "cc_C", "cc_NC", "cc_SGT", "cc_SLE", "cc_SLT", "cc_SGE", "cc_UGT", "cc_ULE"]
CC[2], CC[3], CC[8], CC[9] = "cc_EQ", "cc_NE", "cc_ULT", "cc_UGE"  # aliases Z/NZ/C/NC
ALU = ["ADD", "ADDC", "SUB", "SUBC", "CMP", "XOR", "AND", "OR"]
BITOP = ["BFLDL", "BFLDH", "BCMP", "BMOVN", "BMOV", "BOR", "BAND", "BXOR"]
SHIFT = ["ROL", "ROR", "SHL", "SHR"]

RW = [f"R{i}" for i in range(16)]
RB = [("RL" if i % 2 == 0 else "RH") + str(i // 2) for i in range(16)]


def s8(x):
    return x - 256 if x & 0x80 else x


class Ctx:
    """Data-addressing context valid for one instruction."""
    __slots__ = ("dpp", "ext", "extr", "regs", "mregs")

    def __init__(self, dpp=None):
        self.dpp = list(dpp) if dpp else [0, 1, 2, 3]
        self.ext = None   # ("P", page, n) or ("S", seg, n)
        self.extr = 0     # remaining instructions with ESFR addressing
        self.regs = {}    # known GPR constants (from MOV Rw,#imm)
        self.mregs = {}   # GPR loaded from a memory word (MOV Rw,mem) -> phys

    def copy(self):
        c = Ctx(self.dpp)
        c.ext, c.extr, c.regs, c.mregs = self.ext, self.extr, dict(self.regs), dict(self.mregs)
        return c

    def key(self):
        return (tuple(self.dpp), self.ext, self.extr)

    def phys(self, a):
        if self.ext:
            kind, v, _ = self.ext
            if kind == "S":
                return (v << 16) | a
            return (v << 14) | (a & 0x3FFF)
        return (self.dpp[a >> 14] << 14) | (a & 0x3FFF)


class Insn:
    __slots__ = ("addr", "size", "mn", "ops", "flow", "targets", "refs", "raw", "effect", "store", "slot")

    def __init__(self, addr, size, mn, ops="", flow=None, targets=(), refs=(), effect=None):
        self.addr, self.size, self.mn, self.ops = addr, size, mn, ops
        self.flow = flow          # None | "jmp" | "cjmp" | "call" | "ret" | "ijmp" | "stop"
        self.targets = list(targets)
        self.refs = list(refs or ())  # (phys, "r"/"w"/"rw"/"a")
        self.effect = effect      # callable(ctx) -> None, applied after the insn
        self.raw = b""
        self.store = None         # (phys, const) for MOV mem,Rw with a known constant
        self.slot = None          # CALLI/JMPI through a pointer loaded from memory


class Disasm:
    def __init__(self, img, cal):
        self.img = img
        self.cal = cal  # phys -> name
        self.cal_sorted = sorted(cal)

    # ----- operand helpers -------------------------------------------------
    def reg(self, r, ctx, byte=False):
        if r >= 0xF0:
            return (RB if byte else RW)[r & 15], None
        if ctx.extr:
            a = 0xF000 + 2 * r
            return ESFR.get(a, f"ESFR_{a:04X}"), a
        a = 0xFE00 + 2 * r
        return SFR.get(a, f"SFR_{a:04X}"), a

    def bitoff(self, b, ctx):
        if b >= 0xF0:
            return RW[b & 15], None
        if b >= 0x80:
            a = (0xF100 if ctx.extr else 0xFF00) + 2 * (b - 0x80)
            tbl = ESFR if ctx.extr else SFR
            return BIT_SFR.get(a) or tbl.get(a, f"{'ESFR' if ctx.extr else 'SFR'}_{a:04X}"), a
        a = 0xFD00 + 2 * b
        return f"0x{a:04X}", a

    def mem(self, m, ctx):
        p = ctx.phys(m)
        if 0xF000 <= p < 0x10000 and not ctx.ext:
            name = SFR.get(p) or ESFR.get(p)
            if name:
                return name, p
        return f"0x{m:04X}", p

    def label_for(self, p):
        if p in self.cal:
            return self.cal[p]
        import bisect
        i = bisect.bisect_right(self.cal_sorted, p) - 1
        if i >= 0 and p - self.cal_sorted[i] < 0x40:
            base = self.cal_sorted[i]
            return f"{self.cal[base]}+{p - base}"
        return None

    # ----- decoder ---------------------------------------------------------
    def decode(self, a, ctx):
        img = self.img
        if a + 1 >= len(img):
            return None
        op = img[a]
        b1 = img[a + 1]
        b2 = img[a + 2] if a + 2 < len(img) else 0
        b3 = img[a + 3] if a + 3 < len(img) else 0
        w = b2 | b3 << 8
        n, m = b1 >> 4, b1 & 15
        hi, lo = op >> 4, op & 15
        seg = a & ~0xFFFF
        I = Insn

        def mk(size, mn, ops="", **kw):
            ins = I(a, size, mn, ops, **kw)
            ins.raw = img[a:a + size]
            return ins

        if lo <= 9 and hi <= 7:
            name = ALU[hi]
            byte = lo & 1
            mnb = name + ("B" if byte else "")
            R = RB if byte else RW
            if lo in (0, 1):
                return mk(2, mnb, f"{R[n]}, {R[m]}")
            if lo in (2, 3):
                r, _ = self.reg(b1, ctx, byte)
                s, p = self.mem(w, ctx)
                return mk(4, mnb, f"{r}, {s}", refs=[(p, "r")])
            if lo in (4, 5):
                r, _ = self.reg(b1, ctx, byte)
                s, p = self.mem(w, ctx)
                return mk(4, mnb, f"{s}, {r}", refs=[(p, "rw")])
            if lo == 6:
                r, _ = self.reg(b1, ctx)
                return mk(4, mnb, f"{r}, #0x{w:04X}")
            if lo == 7:
                r, _ = self.reg(b1, ctx, True)
                return mk(4, mnb, f"{r}, #0x{b2:02X}")
            # lo 8/9: Rw,[Rw] / [Rw+] / #data3
            if m & 8:
                ind = f"[{RW[m & 3]}+]" if m & 4 else f"[{RW[m & 3]}]"
                return mk(2, mnb, f"{R[n]}, {ind}")
            return mk(2, mnb, f"{R[n]}, #{m & 7}")

        if lo == 0xA:
            if hi <= 7:
                q = b1
                if hi in (0, 1):  # BFLDL: 0A QQ mask data / BFLDH: 1A QQ data mask
                    s, _ = self.bitoff(b1, ctx)
                    mask, data = (b2, b3) if hi == 0 else (b3, b2)
                    return mk(4, BITOP[hi], f"{s}, #0x{mask:02X}, #0x{data:02X}")
                # bitaddr ops: op QQ ZZ qz  (src QQ.q, dst ZZ.z)
                s1, _ = self.bitoff(b1, ctx)
                s2, _ = self.bitoff(b2, ctx)
                return mk(4, BITOP[hi], f"{s2}.{b3 & 15}, {s1}.{b3 >> 4}")
            if hi <= 0xB:
                mn = ["JB", "JNB", "JBC", "JNBS"][hi - 8]
                s, _ = self.bitoff(b1, ctx)
                t = seg | ((a + 4 + 2 * s8(b2)) & 0xFFFF)
                return mk(4, mn, f"{s}.{b3 >> 4}, loc_{t:06X}", flow="cjmp", targets=[t])
            if hi == 0xC:  # CALLA cc,caddr
                t = seg | w
                return mk(4, "CALLA", f"{CC[b1 >> 4]}, sub_{t:06X}", flow="call", targets=[t])
            if hi == 0xD:  # CALLS seg,caddr
                t = (b1 << 16) | w
                return mk(4, "CALLS", f"sub_{t:06X}", flow="call", targets=[t])
            if hi == 0xE:  # JMPA cc,caddr
                t = seg | w
                cc = b1 >> 4
                return mk(4, "JMPA", f"{CC[cc]}, loc_{t:06X}", flow="jmp" if cc == 0 else "cjmp", targets=[t])
            t = (b1 << 16) | w  # JMPS
            return mk(4, "JMPS", f"loc_{t:06X}", flow="jmp", targets=[t])

        if lo == 0xB:
            if hi in (0, 1):
                return mk(2, ["MUL", "MULU"][hi], f"{RW[n]}, {RW[m]}")
            if hi == 2:
                return mk(2, "PRIOR", f"{RW[n]}, {RW[m]}")
            if 4 <= hi <= 7:
                return mk(2, ["DIV", "DIVU", "DIVL", "DIVLU"][hi - 4], RW[n])
            if hi == 9:
                return mk(2, "TRAP", f"#0x{b1 >> 1:02X}")
            if hi == 0xA:
                ins = mk(2, "CALLI", f"{CC[n]}, [{RW[m]}]", flow="call")
                ins.slot = ctx.mregs.get(m)
                return ins
            if hi == 0xB:
                t = seg | ((a + 2 + 2 * s8(b1)) & 0xFFFF)
                return mk(2, "CALLR", f"sub_{t:06X}", flow="call", targets=[t])
            if hi == 0xC:
                return mk(2, "RET", flow="ret")
            if hi == 0xD:
                return mk(2, "RETS", flow="ret")
            if hi == 0xE:
                r, _ = self.reg(b1, ctx)
                return mk(2, "RETP", r, flow="ret")
            if hi == 0xF:
                return mk(2, "RETI", flow="ret")
            return None

        if lo == 0xC:
            if hi <= 7:
                mn = SHIFT[hi >> 1]
                if hi & 1:
                    return mk(2, mn, f"{RW[m]}, #{n}")
                return mk(2, mn, f"{RW[n]}, {RW[m]}")
            if hi == 9:
                cc = n
                ins = mk(2, "JMPI", f"{CC[cc]}, [{RW[m]}]", flow="ijmp" if cc == 0 else None)
                ins.slot = ctx.mregs.get(m)
                return ins
            if hi == 0xA:
                return mk(2, "ASHR", f"{RW[n]}, {RW[m]}")
            if hi == 0xB:
                return mk(2, "ASHR", f"{RW[m]}, #{n}")
            if hi == 0xC:
                return mk(2, "NOP")
            if hi == 0xD:  # EXTx Rw,#irang
                sub, cnt = b1 >> 6, ((b1 >> 4) & 3) + 1
                mn = ["EXTS", "EXTP", "EXTSR", "EXTPR"][sub]
                val = ctx.regs.get(m)
                kind = "S" if sub in (0, 2) else "P"

                def eff(c, kind=kind, val=val, cnt=cnt, er=sub >= 2):
                    c.ext = (kind, val, cnt) if val is not None else None
                    if er:
                        c.extr = cnt
                note = f"    ; {RW[m]}=0x{val:X}" if val is not None else ""
                return mk(2, mn, f"{RW[m]}, #{cnt}{note}", effect=eff)
            if hi == 0xE:
                r, _ = self.reg(b1, ctx)
                return mk(2, "PUSH", r)
            if hi == 0xF:
                r, _ = self.reg(b1, ctx)
                return mk(2, "POP", r)
            return None

        if lo == 0xD:
            t = seg | ((a + 2 + 2 * s8(b1)) & 0xFFFF)
            return mk(2, "JMPR", f"{CC[hi]}, loc_{t:06X}", flow="jmp" if hi == 0 else "cjmp", targets=[t])

        if lo in (0xE, 0xF):
            s, _ = self.bitoff(b1, ctx)
            return mk(2, "BCLR" if lo == 0xE else "BSET", f"{s}.{hi}")

        # ---------------- rows 8..F, columns 0..9 ----------------
        if hi in (8, 9, 0xA, 0xB):
            cmp_mn = ["CMPI1", "CMPI2", "CMPD1", "CMPD2"][hi - 8]
            if lo == 0:
                return mk(2, cmp_mn, f"{RW[m]}, #{n}")
            if lo == 1:
                return mk(2, ["NEG", "CPL", "NEGB", "CPLB"][hi - 8], (RW if hi < 0xA else RB)[n])
            if lo == 2:
                r, _ = self.reg(b1, ctx)
                s, p = self.mem(w, ctx)
                return mk(4, cmp_mn, f"{r}, {s}", refs=[(p, "r")])
            if lo == 3:
                return mk(4, "co" + "%02X" % op, img[a + 1:a + 4].hex())
            if lo == 4:
                s, p = self.mem(w, ctx)
                if hi == 8:
                    return mk(4, "MOV", f"[{RW[m]}], {s}", refs=[(p, "r")])
                if hi == 9:
                    return mk(4, "MOV", f"{s}, [{RW[m]}]", refs=[(p, "w")])
                if hi == 0xA:
                    return mk(4, "MOVB", f"[{RW[m]}], {s}", refs=[(p, "r")])
                return mk(4, "MOVB", f"{s}, [{RW[m]}]", refs=[(p, "w")])
            if lo == 5:
                special = {0xA5: "DISWDT", 0xB5: "EINIT", 0x85: "ENWDT"}
                if op in special:
                    return mk(4, special[op])
                return None
            if lo == 6:
                r, _ = self.reg(b1, ctx)
                return mk(4, cmp_mn, f"{r}, #0x{w:04X}")
            if lo == 7:
                special = {0x87: "IDLE", 0x97: "PWRDN", 0xA7: "SRVWDT", 0xB7: "SRST"}
                return mk(4, special[op], flow="stop" if op == 0xB7 else None)
            if lo == 8:
                if hi == 8:
                    return mk(2, "MOV", f"[-{RW[m]}], {RW[n]}")
                if hi == 9:
                    return mk(2, "MOV", f"{RW[n]}, [{RW[m]}+]")
                if hi == 0xA:
                    return mk(2, "MOV", f"{RW[n]}, [{RW[m]}]")
                return mk(2, "MOV", f"[{RW[m]}], {RW[n]}")
            if lo == 9:
                if hi == 8:
                    return mk(2, "MOVB", f"[-{RW[m]}], {RB[n]}")
                if hi == 9:
                    return mk(2, "MOVB", f"{RB[n]}, [{RW[m]}+]")
                if hi == 0xA:
                    return mk(2, "MOVB", f"{RB[n]}, [{RW[m]}]")
                return mk(2, "MOVB", f"[{RW[m]}], {RB[n]}")

        if hi in (0xC, 0xD, 0xE, 0xF):
            if lo == 0:
                if hi == 0xC:
                    return mk(2, "MOVBZ", f"{RW[n]}, {RB[m]}")
                if hi == 0xD:
                    return mk(2, "MOVBS", f"{RW[n]}, {RB[m]}")
                if hi == 0xE:
                    def eff(c, r=m, v=n):
                        c.regs[r] = v
                    return mk(2, "MOV", f"{RW[m]}, #{n}", effect=eff)
                return mk(2, "MOV", f"{RW[n]}, {RW[m]}")
            if lo == 1:
                if hi == 0xD:
                    sub, cnt = b1 >> 6, ((b1 >> 4) & 3) + 1
                    if sub == 2:
                        def eff(c, cnt=cnt):
                            c.extr = cnt
                        return mk(2, "EXTR", f"#{cnt}", effect=eff)
                    return mk(2, "ATOMIC", f"#{cnt}")
                if hi == 0xE:
                    return mk(2, "MOVB", f"{RB[m]}, #{n}")
                if hi == 0xF:
                    return mk(2, "MOVB", f"{RB[n]}, {RB[m]}")
                return None
            if lo == 2:
                r, ra = self.reg(b1, ctx, hi == 0xC or hi == 0xD)
                if hi == 0xE:  # PCALL reg,caddr
                    t = seg | w
                    return mk(4, "PCALL", f"{r}, sub_{t:06X}", flow="call", targets=[t])
                s, p = self.mem(w, ctx)
                if hi == 0xC:
                    return mk(4, "MOVBZ", f"{self.reg(b1, ctx)[0]}, {s}", refs=[(p, "r")])
                if hi == 0xD:
                    return mk(4, "MOVBS", f"{self.reg(b1, ctx)[0]}, {s}", refs=[(p, "r")])
                def eff(c, b1=b1, p=p):
                    if b1 >= 0xF0:
                        c.regs.pop(b1 & 15, None)
                        c.mregs[b1 & 15] = p
                return mk(4, "MOV", f"{self.reg(b1, ctx)[0]}, {s}", refs=[(p, "r")], effect=eff)
            if lo == 3:
                if hi == 0xF:
                    r, _ = self.reg(b1, ctx, True)
                    s, p = self.mem(w, ctx)
                    return mk(4, "MOVB", f"{r}, {s}", refs=[(p, "r")])
                return mk(4, "co" + "%02X" % op, img[a + 1:a + 4].hex())
            if lo == 4:
                p = None
                ann = self._abs16(w, ctx)
                if hi == 0xC:
                    return mk(4, "MOV", f"[{RW[m]}+#0x{w:04X}], {RW[n]}", refs=ann and [(ann, "w")])
                if hi == 0xD:
                    return mk(4, "MOV", f"{RW[n]}, [{RW[m]}+#0x{w:04X}]", refs=ann and [(ann, "r")], effect=self._clobber(0xF0 | n))
                if hi == 0xE:
                    return mk(4, "MOVB", f"[{RW[m]}+#0x{w:04X}], {RB[n]}", refs=ann and [(ann, "w")])
                return mk(4, "MOVB", f"{RB[n]}, [{RW[m]}+#0x{w:04X}]", refs=ann and [(ann, "r")])
            if lo == 5:
                if hi in (0xC, 0xD):
                    r, _ = self.reg(b1, ctx, True)
                    s, p = self.mem(w, ctx)
                    return mk(4, "MOVBZ" if hi == 0xC else "MOVBS", f"{s}, {r}", refs=[(p, "w")])
                return None
            if lo == 6:
                r, ra = self.reg(b1, ctx)
                if hi == 0xC:
                    return mk(4, "SCXT", f"{r}, #0x{w:04X}")
                if hi == 0xD:
                    s, p = self.mem(w, ctx)
                    return mk(4, "SCXT", f"{r}, {s}", refs=[(p, "r")])
                if hi == 0xE:  # MOV reg,#data16
                    def eff(c, b1=b1, w=w):
                        if b1 >= 0xF0:
                            c.regs[b1 & 15] = w
                        elif b1 < 4 and not c.extr:
                            c.dpp[b1] = w & 0x3FF
                    refs = []
                    if b1 >= 0xF0 and ctx.phys(w) in self.cal:
                        refs = [(ctx.phys(w), "addr")]  # table address passed to a helper
                    return mk(4, "MOV", f"{r}, #0x{w:04X}", effect=eff, refs=refs)
                s, p = self.mem(w, ctx)
                ins = mk(4, "MOV", f"{s}, {r}", refs=[(p, "w")])
                if b1 >= 0xF0 and (b1 & 15) in ctx.regs:
                    v = ctx.regs[b1 & 15]
                    ins.store = (p, v)
                    if 0xFE00 <= p <= 0xFE06 and not ctx.ext:
                        def eff(c, i=(p - 0xFE00) // 2, v=v):
                            c.dpp[i] = v & 0x3FF
                        ins.effect = eff
                return ins
            if lo == 7:
                if hi == 0xD:  # EXTP/EXTS #,#
                    sub, cnt = b1 >> 6, ((b1 >> 4) & 3) + 1
                    mn = ["EXTS", "EXTP", "EXTSR", "EXTPR"][sub]
                    if sub in (0, 2):
                        v = b2
                    else:
                        v = (b3 << 8 | b2) & 0x3FF
                    kind = "S" if sub in (0, 2) else "P"

                    def eff(c, kind=kind, v=v, cnt=cnt, er=sub >= 2):
                        c.ext = (kind, v, cnt)
                        if er:
                            c.extr = cnt
                    return mk(4, mn, f"#0x{v:X}, #{cnt}", effect=eff)
                if hi == 0xE:
                    r, _ = self.reg(b1, ctx, True)
                    return mk(4, "MOVB", f"{r}, #0x{b2:02X}")
                if hi == 0xF:
                    r, _ = self.reg(b1, ctx, True)
                    s, p = self.mem(w, ctx)
                    return mk(4, "MOVB", f"{s}, {r}", refs=[(p, "w")])
                return None
            if lo == 8:
                if hi == 0xC:
                    return mk(2, "MOV", f"[{RW[n]}], [{RW[m]}]")
                if hi == 0xD:
                    return mk(2, "MOV", f"[{RW[n]}+], [{RW[m]}]")
                if hi == 0xE:
                    return mk(2, "MOV", f"[{RW[n]}], [{RW[m]}+]")
                return None
            if lo == 9:
                if hi == 0xC:
                    return mk(2, "MOVB", f"[{RW[n]}], [{RW[m]}]")
                if hi == 0xD:
                    return mk(2, "MOVB", f"[{RW[n]}+], [{RW[m]}]")
                if hi == 0xE:
                    return mk(2, "MOVB", f"[{RW[n]}], [{RW[m]}+]")
                return None
        return None

    def _abs16(self, w, ctx):
        """[Rw+#d16]: absolute under EXTP/EXTS; without a prefix only annotated
        when the DPP-resolved base falls into the calibration area (table+index)."""
        if ctx.ext:
            return ctx.phys(w)
        p = ctx.phys(w)
        if 0x74000 <= p < 0x7C000:
            return p
        return None

    @staticmethod
    def _clobber(b1):
        def eff(c):
            if b1 >= 0xF0:
                c.regs.pop(b1 & 15, None)
        return eff


def step_ctx(ctx, ins):
    """Context for the next sequential instruction."""
    c = ctx.copy()
    if c.ext:
        kind, v, left = c.ext
        c.ext = (kind, v, left - 1) if left > 1 else None
    if c.extr:
        c.extr -= 1
    # any write to a GPR invalidates the constant we know for it (rough)
    if ins.ops:
        first = ins.ops.split(",")[0].strip()
        if first in RW and ins.mn not in ("CMP", "CMPB", "PUSH", "JMPI", "CALLI") and not ins.mn.startswith("J"):
            c.regs.pop(RW.index(first), None)
            c.mregs.pop(RW.index(first), None)
    if ins.effect:
        ins.effect(c)
    if ins.flow in ("call",):
        c.regs = {}
        c.mregs = {}
    return c


# DPP values set by the application start-up code at 0x01A720 (DPP0/DPP1 point
# to the active calibration copy 0x74000/0x78000, or 0x80000/0x84000 if the
# primary copy is invalid).
INIT_DPP = [0x1D, 0x1E, 0x3C, 0x03]
CODE_REGIONS = [(0x000200, 0x004000), (0x018000, 0x02C000), (0x030000, 0x050000)]


def analyse(img, cal, entries, init_dpp):
    """Two passes: the first one discovers call / pointer targets that are only
    reachable from gap-filled code; the second starts from all of them before
    gap filling, so real entry points win over misaligned gap guesses."""
    dis, insns, funcs, labels, bad = _analyse(img, cal, entries, init_dpp)
    seeds = list(entries)
    seeds += [(a, k) for a, k in funcs.items() if k.startswith("ptr")]
    seeds += [(a, "ptr") for a in _ptr_targets(insns) if a not in funcs or funcs[a] == "gap"]
    return _analyse(img, cal, seeds, init_dpp)


def _ptr_targets(insns):
    stores = collections.defaultdict(set)
    sites = collections.defaultdict(set)
    for ins in insns.values():
        if ins.store:
            stores[ins.store[0]].add(ins.store[1])
        if ins.slot is not None:
            sites[ins.slot].add(ins.addr & ~0xFFFF)
    return {seg | v for slot, segs in sites.items() for v in stores.get(slot, ()) for seg in segs}


def _analyse(img, cal, entries, init_dpp):
    dis = Disasm(img, cal)
    insns = {}
    covered = {}        # word address -> start of the instruction covering it
    funcs = {}          # address -> how it was found
    labels = set()
    bad = []

    def explore(work):
        while work:
            a, ctx = work.popleft()
            while True:
                if a in insns:
                    break
                if not (0 <= a < len(img) - 1) or a & 1 or a in covered:
                    bad.append(a)
                    break
                ins = dis.decode(a, ctx)
                if ins is None or img[a:a + 4] == b"\xff\xff\xff\xff" or (ins.size == 4 and a + 2 in covered):
                    bad.append(a)
                    break
                insns[a] = ins
                for k in range(0, ins.size, 2):
                    covered[a + k] = a
                nxt = step_ctx(ctx, ins)
                for t in ins.targets:
                    if ins.flow == "call":
                        if t not in funcs:
                            funcs[t] = "call"
                            work.append((t, Ctx(init_dpp)))
                    else:
                        labels.add(t)
                        work.append((t, nxt.copy()))
                if ins.flow in ("jmp", "ret", "ijmp", "stop"):
                    break
                a += ins.size
                ctx = nxt

    def trial(a):
        """Linear decode until an unconditional end of flow; True if it looks like code."""
        ctx = Ctx(init_dpp)
        n = 0
        while n < 4000:
            if a in insns:
                return n > 0
            if a in covered:
                return False
            ins = dis.decode(a, ctx)
            if ins is None or img[a:a + 2] == b"\xff\xff" or (ins.size == 4 and a + 2 in covered):
                return False
            for t in ins.targets:
                if not (0 <= t < len(img)) or img[t:t + 2] == b"\xff\xff":
                    return False
            n += 1
            if ins.flow in ("jmp", "ret", "ijmp", "stop"):
                return True
            ctx = step_ctx(ctx, ins)
            a += ins.size
        return False

    work = collections.deque()
    for e, kind in entries:
        work.append((e, Ctx(init_dpp)))
        if kind == "label":
            labels.add(e)
        else:
            funcs[e] = "entry" if kind == "func" else kind
    explore(work)

    while True:
        progress = False
        # 1) code pointers stored into RAM slots and called through CALLI/JMPI
        stores = collections.defaultdict(set)
        sites = collections.defaultdict(set)
        for ins in insns.values():
            if ins.store:
                stores[ins.store[0]].add(ins.store[1])
            if ins.slot is not None:
                sites[ins.slot].add(ins.addr & ~0xFFFF)
        for slot, segs in sites.items():
            for v in stores.get(slot, ()):
                for seg in segs:
                    t = seg | v
                    if t not in funcs and t not in insns:
                        funcs[t] = f"ptr 0x{slot:04X}"
                        work.append((t, Ctx(init_dpp)))
                        progress = True
        explore(work)
        if progress:
            continue
        # 2) gap filling: undecoded non-FF bytes in code regions
        for lo, hi in CODE_REGIONS:
            a = lo
            while a < hi:
                if a in covered:
                    a += 2
                    continue
                if img[a:a + 2] == b"\xff\xff" or img[a:a + 2] == b"\x00\x00" and img[a + 2:a + 4] in (b"\x00\x00", b"\xff\xff"):
                    a += 2
                    continue
                if trial(a):
                    funcs[a] = "gap"
                    work.append((a, Ctx(init_dpp)))
                    explore(work)
                    progress = True
                a += 2
        if not progress:
            break
    return dis, insns, funcs, labels, bad


def load_cal(path):
    cal = {}
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            a = int(row["address"], 16)
            cal.setdefault(a, row["name"])
    return cal


def main(binp, calp, outdir, extra=()):
    img = open(binp, "rb").read()
    cal = load_cal(calp)
    entries = []
    for v in range(0, 0x200, 4):
        if img[v] == 0xFA:
            entries.append((v, "label"))
        if img[0x4000 + v] == 0xFA:
            entries.append((0x4000 + v, "label"))
    for e in extra:
        entries.append((e, "func"))
    dis, insns, funcs, labels, bad = analyse(img, cal, entries, init_dpp=INIT_DPP)
    os.makedirs(outdir, exist_ok=True)

    xref = collections.defaultdict(list)
    func_of = {}
    fs = sorted(funcs)
    import bisect
    for a in insns:
        i = bisect.bisect_right(fs, a) - 1
        func_of[a] = fs[i] if i >= 0 else None

    with open(os.path.join(outdir, "ST10.asm"), "w", encoding="utf-8") as f:
        f.write("; ST10 (Январь 7.3, j73s_2.20.2) — auto-generated by tools/st10dis.py\n")
        f.write("; addresses are physical (segment<<16 | offset)\n\n")
        prev_end = None
        for a in sorted(insns):
            ins = insns[a]
            if prev_end is not None and a != prev_end:
                f.write("\n")
            if a in funcs:
                f.write(f"\n;{'=' * 70}\nsub_{a:06X}:    ; found by: {funcs[a]}\n")
            elif a in labels:
                vec = VECTORS.get(a) or VECTORS.get(a - 0x4000)
                f.write(f"loc_{a:06X}:" + (f"    ; vector {vec}" if vec else "") + "\n")
            cm = []
            for p, rw in ins.refs or ():
                if p is None:
                    continue
                name = dis.label_for(p)
                if name:
                    cm.append(f"[{p:05X}] {name}")
                    xref[p].append((a, rw))
                elif not (0xF000 <= p < 0x10000):
                    cm.append(f"[{p:05X}]")
            line = f"  {a:06X}  {ins.raw.hex(' '):<12} {ins.mn:<7} {ins.ops}"
            if cm:
                line = f"{line:<64} ; " + "; ".join(cm)
            f.write(line + "\n")
            prev_end = a + ins.size

    with open(os.path.join(outdir, "functions.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["address", "found_by", "callers", "calibrations_used"])
        callers = collections.Counter()
        for ins in insns.values():
            if ins.flow == "call":
                for t in ins.targets:
                    callers[t] += 1
        used = collections.defaultdict(set)
        for p, lst in xref.items():
            for a, _ in lst:
                used[func_of[a]].add(dis.label_for(p))
        for fa in sorted(funcs):
            w.writerow([f"0x{fa:06X}", funcs[fa], callers[fa], " | ".join(sorted(used.get(fa, ())))])

    with open(os.path.join(outdir, "xrefs.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cal_address", "name", "insn_address", "access", "function"])
        for p in sorted(xref):
            for a, rw in sorted(xref[p]):
                fa = func_of[a]
                w.writerow([f"0x{p:05X}", dis.label_for(p), f"0x{a:06X}", rw, f"sub_{fa:06X}" if fa is not None else ""])

    code = sum(i.size for i in insns.values())
    direct = sum(1 for p in cal if p in xref)
    print(f"insns {len(insns)}  code bytes {code}  functions {len(funcs)}  "
          f"decode stops {len(bad)}  calibrations referenced {direct}/{len(cal)}")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2], sys.argv[3], [int(x, 0) for x in sys.argv[4:]])
