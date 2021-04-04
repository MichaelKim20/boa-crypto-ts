/*******************************************************************************

    Includes various useful functions

    Copyright:
        Copyright (c) 2020-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

import JSBI from "jsbi";

/**
 * The byte order
 */
export enum Endian
{
    Little,
    Big
}

export class Utils
{
    /**
     * Read from the hex string
     * @param hex The hex string
     * @param target The buffer to output
     * @param endian The byte order
     * @returns The output buffer
     */
    public static readFromString (hex: string, target?: Buffer, endian: Endian = Endian.Little): Buffer
    {
        let start = (hex.substr(0, 2) == '0x') ? 2 : 0;
        let length = (hex.length - start) >> 1;
        if (target === undefined)
            target = Buffer.alloc(length);

        if (endian == Endian.Little)
        {
            for (let pos = 0, idx = start; idx < length * 2 + start; idx += 2, pos++)
                target[length - pos - 1] = parseInt(hex.substr(idx, 2), 16);
        }
        else
        {
            for (let pos = 0, idx = start; idx < length * 2 + start; idx += 2, pos++)
                target[pos] = parseInt(hex.substr(idx, 2), 16);
        }
        return target;
    }

    /**
     * Write to the hex string
     * @param source The buffer to input
     * @param endian The byte order
     * @returns The hex string
     */
    public static writeToString (source: Buffer, endian: Endian = Endian.Little): string
    {
        if (source.length == 0)
            return '';

        if (endian == Endian.Little)
        {
            let hex: Array<string> = [];
            for (let idx = source.length-1; idx >= 0; idx--) {
                hex.push((source[idx] >>> 4).toString(16));
                hex.push((source[idx] & 0xF).toString(16));
            }
            return '0x' + hex.join("");
        }
        else
            return '0x' + source.toString("hex");
    }

    /**
     * Writes little endian 64-bits Big integer value to an allocated buffer
     * See https://github.com/nodejs/node/blob/88fb5a5c7933022de750745e51e5dc0996a1e2c4/lib/internal/buffer.js#L573-L592
     * @param buffer The allocated buffer
     * @param value  The big integer value
     */
    public static writeJSBigIntLE (buffer: Buffer, value: JSBI)
    {
        let lo =
            JSBI.toNumber(
                JSBI.bitwiseAnd(
                    value,
                    JSBI.BigInt(0xffffffff)
                )
            );
        buffer[0] = lo;
        lo = lo >> 8;
        buffer[1] = lo;
        lo = lo >> 8;
        buffer[2] = lo;
        lo = lo >> 8;
        buffer[3] = lo;

        let hi =
            JSBI.toNumber(
                JSBI.bitwiseAnd(
                    JSBI.signedRightShift(
                        value,
                        JSBI.BigInt(32)
                    ),
                    JSBI.BigInt(0xffffffff)
                )
            );
        buffer[4] = hi;
        hi = hi >> 8;
        buffer[5] = hi;
        hi = hi >> 8;
        buffer[6] = hi;
        hi = hi >> 8;
        buffer[7] = hi;
    }

    /**
     * Reads little endian 64-bits Big integer value to an allocated buffer
     * An exception occurs when the size of the remaining data is less than the required.
     * See https://github.com/nodejs/node/blob/88fb5a5c7933022de750745e51e5dc0996a1e2c4/lib/internal/buffer.js#L86-L105
     * @param buffer The allocated buffer
     * @returns The instance of JSBI
     */
    public static readJSBigIntLE (buffer: Buffer): JSBI
    {
        if (buffer.length < 8)
            throw new Error(`Requested 8 bytes but only ${buffer.length} bytes available`)

        let offset = 0;
        const lo = buffer[offset] +
            buffer[++offset] * 2 ** 8 +
            buffer[++offset] * 2 ** 16 +
            buffer[++offset] * 2 ** 24;

        const hi = buffer[++offset] +
            buffer[++offset] * 2 ** 8 +
            buffer[++offset] * 2 ** 16 +
            buffer[++offset] * 2 ** 24;

        return JSBI.add(
            JSBI.BigInt(lo),
            JSBI.leftShift(
                JSBI.BigInt(hi),
                JSBI.BigInt(32)
            ));
    }

    /**
     * Compare the two Buffers, This compares the two buffers from the back to the front.
     * If a is greater than b, it returns a positive number,
     * if a is less than b, it returns a negative number,
     * and if a and b are equal, it returns zero.
     */
    public static compareBuffer (a: Buffer, b: Buffer): number
    {
        let min_length = Math.min(a.length,  b.length)
        for (let idx = 0; idx < min_length; idx++)
        {
            let a_value = a[a.length - 1 - idx];
            let b_value = b[b.length - 1 - idx];
            if (a_value !== b_value)
                return (a_value - b_value)
        }

        return a.length - b.length;
    }
}
