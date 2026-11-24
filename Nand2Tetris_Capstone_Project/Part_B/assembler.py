"""Assemble Hack assembly language into 16-bit machine instructions."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


PREDEFINED_SYMBOLS = {
    **{f"R{number}": number for number in range(16)},
    "SP": 0,
    "LCL": 1,
    "ARG": 2,
    "THIS": 3,
    "THAT": 4,
    "SCREEN": 16384,
    "KBD": 24576,
}

COMP_BITS = {
    "0": "0101010",
    "1": "0111111",
    "-1": "0111010",
    "D": "0001100",
    "A": "0110000",
    "M": "1110000",
    "!D": "0001101",
    "!A": "0110001",
    "!M": "1110001",
    "-D": "0001111",
    "-A": "0110011",
    "-M": "1110011",
    "D+1": "0011111",
    "A+1": "0110111",
    "M+1": "1110111",
    "D-1": "0001110",
    "A-1": "0110010",
    "M-1": "1110010",
    "D+A": "0000010",
    "A+D": "0000010",
    "D+M": "1000010",
    "M+D": "1000010",
    "D-A": "0010011",
    "D-M": "1010011",
    "A-D": "0000111",
    "M-D": "1000111",
    "D&A": "0000000",
    "A&D": "0000000",
    "D&M": "1000000",
    "M&D": "1000000",
    "D|A": "0010101",
    "A|D": "0010101",
    "D|M": "1010101",
    "M|D": "1010101",
}

DEST_BITS = {
    "": "000",
    "M": "001",
    "D": "010",
    "MD": "011",
    "A": "100",
    "AM": "101",
    "AD": "110",
    "AMD": "111",
}

JUMP_BITS = {
    "": "000",
    "JGT": "001",
    "JEQ": "010",
    "JGE": "011",
    "JLT": "100",
    "JNE": "101",
    "JLE": "110",
    "JMP": "111",
}

SYMBOL_PATTERN = re.compile(r"^[A-Za-z_.$:][A-Za-z0-9_.$:]*$")


class AssemblyError(ValueError):
    """Raised when an assembly source line cannot be assembled."""


def clean_lines(source: str) -> list[tuple[str, int]]:
    """Remove comments and blank lines while preserving original line numbers."""
    instructions = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        instruction = line.split("//", maxsplit=1)[0].strip()
        if instruction:
            instructions.append((instruction, line_number))
    return instructions


def _line_error(line_number: int, message: str) -> AssemblyError:
    return AssemblyError(f"line {line_number}: {message}")


def _validate_symbol(symbol: str, line_number: int) -> None:
    if not SYMBOL_PATTERN.fullmatch(symbol):
        raise _line_error(line_number, f"invalid symbol name {symbol!r}")


class Assembler:
    """Perform the label-discovery and instruction-encoding passes."""

    def __init__(self) -> None:
        self.symbol_table = PREDEFINED_SYMBOLS.copy()
        self.label_symbols: set[str] = set()
        self.next_variable_address = 16

    def first_pass(self, instructions: list[tuple[str, int]]) -> None:
        """Record labels using the ROM address of their next instruction."""
        rom_address = 0
        for instruction, line_number in instructions:
            if instruction.startswith("(") or instruction.endswith(")"):
                if not (instruction.startswith("(") and instruction.endswith(")")):
                    raise _line_error(line_number, "malformed label declaration")
                label = instruction[1:-1]
                _validate_symbol(label, line_number)
                if rom_address > 32767:
                    raise _line_error(line_number, "label address exceeds 32767")
                if label in self.label_symbols:
                    print(
                        f"Warning: Duplicate label '{label}' at line {line_number}",
                        file=sys.stderr,
                    )
                elif label in PREDEFINED_SYMBOLS:
                    raise _line_error(
                        line_number,
                        f"label {label!r} conflicts with a predefined symbol",
                    )
                else:
                    self.symbol_table[label] = rom_address
                    self.label_symbols.add(label)
            else:
                rom_address += 1
                if rom_address > 32768:
                    raise _line_error(line_number, "program exceeds the 32K ROM address space")

    def _address_for(self, symbol: str, line_number: int) -> int:
        if symbol in self.symbol_table:
            return self.symbol_table[symbol]
        _validate_symbol(symbol, line_number)
        if self.next_variable_address > 32767:
            raise _line_error(line_number, "no available 15-bit address for variable")
        address = self.next_variable_address
        self.symbol_table[symbol] = address
        self.next_variable_address += 1
        return address

    def encode_instruction(self, instruction: str, line_number: int) -> str:
        """Encode one A- or C-instruction as exactly 16 binary digits."""
        if instruction.startswith("@"):
            value = instruction[1:]
            if not value:
                raise _line_error(line_number, "A-instruction is missing an address")
            if value.isascii() and value.isdecimal():
                address = int(value)
                if address > 32767:
                    raise _line_error(
                        line_number, "A-instruction address must be between 0 and 32767"
                    )
            else:
                address = self._address_for(value, line_number)
            return f"0{address:015b}"

        if instruction.count("=") > 1 or instruction.count(";") > 1:
            raise _line_error(line_number, f"invalid C-instruction {instruction!r}")

        has_jump_field = ";" in instruction
        if has_jump_field:
            instruction, jump = instruction.split(";", maxsplit=1)
            if not jump:
                raise _line_error(line_number, "C-instruction is missing a jump mnemonic")
        else:
            jump = ""
        has_destination_field = "=" in instruction
        if has_destination_field:
            destination, computation = instruction.split("=", maxsplit=1)
            if not destination:
                raise _line_error(line_number, "C-instruction is missing a destination mnemonic")
        else:
            destination, computation = "", instruction

        if not computation or computation not in COMP_BITS:
            raise _line_error(line_number, f"unknown computation mnemonic {computation!r}")
        if destination not in DEST_BITS:
            raise _line_error(line_number, f"unknown destination mnemonic {destination!r}")
        if jump not in JUMP_BITS:
            raise _line_error(line_number, f"unknown jump mnemonic {jump!r}")

        return f"111{COMP_BITS[computation]}{DEST_BITS[destination]}{JUMP_BITS[jump]}"

    def assemble(self, source: str) -> list[str]:
        """Return machine-code lines for a complete assembly source string."""
        self.symbol_table = PREDEFINED_SYMBOLS.copy()
        self.label_symbols.clear()
        self.next_variable_address = 16
        instructions = clean_lines(source)
        self.first_pass(instructions)
        machine_code = []
        for instruction, line_number in instructions:
            if instruction.startswith("(") and instruction.endswith(")"):
                continue
            machine_code.append(self.encode_instruction(instruction, line_number))
        return machine_code


def assemble_file(input_path: Path, output_path: Path | None = None) -> Path:
    """Assemble one file, writing its .hack output beside it unless specified."""
    source = input_path.read_text(encoding="utf-8")
    machine_code = Assembler().assemble(source)
    destination = output_path if output_path is not None else input_path.with_suffix(".hack")
    output = "\n".join(machine_code)
    if machine_code:
        output += "\n"
    destination.write_text(output, encoding="ascii")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Translate Hack assembly (.asm) files into machine code (.hack)."
    )
    parser.add_argument("input", type=Path, help="input .asm file")
    parser.add_argument(
        "-o", "--output", type=Path, help="output .hack file (defaults to input name)"
    )
    arguments = parser.parse_args()

    try:
        output_path = assemble_file(arguments.input, arguments.output)
    except (AssemblyError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(f"Assembled {arguments.input} -> {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
