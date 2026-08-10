// SPDX-License-Identifier: Apache-2.0

// Guards bound preservation at the type level. A raw string must not satisfy a
// branded, bounded identifier without passing its validator.

import {type TurnId} from "../../generated/spike.ts";

export const identifier: TurnId = "not-validated";
