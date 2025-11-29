module.exports = {
  apps : [
      {
        name: "PMaster-API",
        script: "./index.js",
        env_production: {
            "DB_USER": "cilantro",
            "DB_PASSWORD": "cilantro",
            "DB_DB": "PMaster",
            "DB_CONNECTION_LIMIT": "10",
            "JWT_SECRET": "superSecretAndLongSecretKeyForJWTs",
            "PORT": "42069",
            "NODE_ENV": "production"
        }
      }
  ]
}