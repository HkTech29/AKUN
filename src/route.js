const Joi = require('joi');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');


async function routeHandler(server) {
    const db = admin.firestore();
   
    server.route({
        method: 'POST',
        path: '/register',
        handler: async (request, h) => {
            const { name, email, password } = request.payload;
            const db = admin.firestore();
    
            const schema = Joi.object({
                name: Joi.string().min(3).max(20).required(),
                email: Joi.string().email().required(),
                password: Joi.string().min(8).required()
            });
    
            const { error } = schema.validate(request.payload, { abortEarly: false });
            if (error) {
                const translatedErrors = error.details.map(err => translateJoiError(err));
                return h.response({ error: true, message: translatedErrors.join(', ') }).code(400);
            }
    
            const userSnapshot = await db.collection('users').where('email', '==', email).get();
            if (!userSnapshot.empty) {
                return h.response({ error: true, message: 'Email sudah digunakan, silakan coba lagi' }).code(400);
            }
    
            const hashedPassword = await argon2.hash(password);
    
            const userRef = db.collection('users').doc();
            await userRef.set({
                name,
                email,
                password: hashedPassword
            });
    
            return h.response({ error: false, message: 'Pengguna berhasil dibuat' }).code(201);
        }
    });
  
}

module.exports = routeHandler;
