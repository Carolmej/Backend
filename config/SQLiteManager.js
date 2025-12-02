import Database from "better-sqlite3";

const openDB = (projectID) => {
    const projectDB = new Database(projectID + '.db');
    projectDB.pragma('journal_mode = WAL');
    return projectDB;
}

const createTables = (projectDB) => {
    projectDB.exec(`
        create table if not exists "modules" (
            "id" integer primary key autoincrement not null,
            "title" text not null,
            "description" text,
            "priority" text,
            "status" text,
            "created_at" timestamp default current_date,
            "updated_at" timestamp default current_date,
            "team_ids" integer
        );

        create table if not exists "tasks" (
            "id" integer primary key autoincrement not null,
            "module_id" integer,
            "title" text not null,
            "description" text,
            "priority" text,
            "status" text,
            "created_at" timestamp default current_date,
            "updated_at" timestamp default current_date,
            "user_ids" integer
        );

        create table if not exists "teams" (
            "id" integer primary key autoincrement not null,
            "name" text not null,
            "description" text
        );

        create table if not exists "teammembers" (
            "team_id" integer,
            "user_id" integer);
        `)
}

export { openDB, createTables };