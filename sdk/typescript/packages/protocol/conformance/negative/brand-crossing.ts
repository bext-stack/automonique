// SPDX-License-Identifier: Apache-2.0

// Guards brand distinctness. Assigning one identifier domain to another must
// not compile; if it does, branding was erased in generation.

import {SessionId, TurnId, type SessionId as SessionIdType} from "../../generated/spike.ts";

const turn = TurnId("t-1");
const session: SessionIdType = turn;
void session;
void SessionId;
