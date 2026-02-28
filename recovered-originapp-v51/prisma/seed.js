/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function main() {
  const email = 'demo@origin.social';
  const username = 'origin_demo';
  const passwordHash = await bcrypt.hash('DemoPass123!', 10);

  const user = await prisma.user.upsert({
    where: { email },
    update: {
      displayName: 'Origin Demo Creator',
    },
    create: {
      email,
      username,
      displayName: 'Origin Demo Creator',
      passwordHash,
      bio: 'Seeded demo creator for local development',
      creatorKeyId: 'demo-key-1',
    },
  });

  const existingVideo = await prisma.video.findFirst({
    where: {
      creatorId: user.id,
      title: 'Origin Demo Reel',
    },
  });

  if (!existingVideo) {
    await prisma.video.create({
      data: {
        creatorId: user.id,
        title: 'Origin Demo Reel',
        description: 'Seeded demo content',
        videoUrl: '/uploads/demo.mp4',
        originBundleId: 'demo.origin.zip',
        originVerified: false,
      },
    });
  }

  console.log('Prisma seed complete.');
  console.log('Demo login:', { email, password: 'DemoPass123!' });
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
