UPDATE flask_rest_api.user
SET is_activated = 1
WHERE id = 5;


ALTER TABLE flask_rest_api.user
ADD category varchar(25);