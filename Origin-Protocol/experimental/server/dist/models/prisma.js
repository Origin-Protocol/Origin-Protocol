"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.prisma = void 0;
const client_1 = require("@prisma/client");
const config_1 = require("../config");
exports.prisma = config_1.config.database.usePrisma ? new client_1.PrismaClient() : null;
//# sourceMappingURL=prisma.js.map