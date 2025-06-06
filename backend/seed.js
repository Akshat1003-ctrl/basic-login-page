// backend/seed.js
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const Role = require('./models/Role');

dotenv.config();

const seedRoles = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });

        console.log('MongoDB Connected for seeding...');

        // Check if roles already exist
        const rolesCount = await Role.countDocuments();
        if (rolesCount > 0) {
            console.log('Roles already exist in the database. No seeding needed.');
            mongoose.disconnect();
            return;
        }

        // Create roles
        const roles = [
            { name: 'user' },
            { name: 'admin' }
        ];

        await Role.insertMany(roles);

        console.log('Roles seeded successfully!');
        mongoose.disconnect();

    } catch (error) {
        console.error('Error seeding roles:', error);
        process.exit(1);
    }
};

seedRoles();