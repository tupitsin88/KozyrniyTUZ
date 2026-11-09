\getenv app_password CLUB_DB_PASSWORD
CREATE ROLE club_app LOGIN PASSWORD :'app_password';
ALTER DATABASE club_membership OWNER TO club_app;
