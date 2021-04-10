/*******************************************************************************

    Includes useful functions for Javascript Big Integer (JSBI)

    Copyright:
        Copyright (c) 2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

import JSBI from 'jsbi';

export class JSBIUtils
{
    public static JSBigInt (from: number|string|boolean|object): JSBI
    {
        return JSBI.BigInt(from);
    }

    public static toInt8 (value: JSBI): number
    {
        return JSBI.toNumber(JSBI.bitwiseAnd(value, JSBI.BigInt(0xFF)));
    }

    public static toInt32 (value: JSBI): number
    {
        return JSBI.toNumber(JSBI.bitwiseAnd(value, JSBI.BigInt(0xFFFFFFFF)));
    }

    public static Sum (values: Array<JSBI>): JSBI
    {
        return values.reduce<JSBI>((sum, n) => {
            return JSBI.add(sum, n)
        }, JSBI.BigInt(0));
    }

    public static SumMultiply (values: Array<JSBI>): JSBI
    {
        let sum = JSBI.BigInt(0);
        for (let i = 0; i < values.length; i += 2)
            sum = JSBI.add(sum, JSBI.multiply(values[i], values[i+1]));
        return sum;
    }
}
