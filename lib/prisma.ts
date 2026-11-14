import { PrismaClient } from '@prisma/client'

// Local development keeps its database next to the schema. A container sets
// DATABASE_URL to a file on a mounted volume instead.
process.env.DATABASE_URL ||= 'file:./dev.db'

const globalForPrisma = global as unknown as { prisma: PrismaClient }

export const prisma =
  globalForPrisma.prisma ||
  new PrismaClient()

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma
