module.exports = {
  apps : [
      {
        name: "PMaster-API",
        script: "./index.js",
        env_production: {
            "DB_USER": "replaceme",
            "DB_PASSWORD": "replaceme",
            "DB_DB": "PMaster",
            "DB_CONNECTION_LIMIT": "10",
            "JWT_SECRET": "superSecretAndLongSecretKeyForJWTs",
            "PORT": "42069",
            "NODE_ENV": "production"
        }
      }
  ]
}