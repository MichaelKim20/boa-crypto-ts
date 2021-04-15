/*******************************************************************************

    Includes a function that generates random bytes

    Copyright:
        Copyright (c) 2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

import * as nacl from 'tweetnacl-ts';

export function randombytes_buf (n: number): Uint8Array
{
    return nacl.randomBytes(n);
}
