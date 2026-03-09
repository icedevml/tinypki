\c stepca

CREATE EXTENSION IF NOT EXISTS pgmq;
SELECT pgmq.create('event_queue');

CREATE OR REPLACE FUNCTION public.tinypki_dispatch_event()
    RETURNS trigger
    LANGUAGE 'plpgsql'
    COST 100
    VOLATILE NOT LEAKPROOF
AS $BODY$
DECLARE
    event_payload jsonb;
    initial_sync_state json;
BEGIN
    SELECT mvalue INTO initial_sync_state
    FROM public.tinypki_indexer_meta
    WHERE mkey = 'initial_sync_state';

    event_payload := jsonb_build_object(
        'initial_sync_state', initial_sync_state::jsonb,
        'operation', TG_OP,
        'table', TG_TABLE_NAME,
        'data', CASE
            WHEN TG_OP = 'DELETE' THEN row_to_json(OLD)::jsonb
            ELSE row_to_json(NEW)::jsonb
        END,
        'old_data', CASE
            WHEN TG_OP = 'UPDATE' THEN row_to_json(OLD)::jsonb
            ELSE NULL
        END
    );

	PERFORM pgmq.send(
        'event_queue',
        event_payload
    );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$BODY$;

CREATE OR REPLACE TRIGGER tinypki_event_insert_x509_certs
    AFTER INSERT
    ON public.x509_certs
    FOR EACH ROW
    EXECUTE FUNCTION public.tinypki_dispatch_event();

CREATE OR REPLACE TRIGGER tinypki_event_insert_x509_certs_data
    AFTER INSERT
    ON public.x509_certs_data
    FOR EACH ROW
    EXECUTE FUNCTION public.tinypki_dispatch_event();

CREATE OR REPLACE TRIGGER tinypki_event_insert_revoked_x509_certs
    AFTER INSERT
    ON public.revoked_x509_certs
    FOR EACH ROW
    EXECUTE FUNCTION public.tinypki_dispatch_event();

CREATE OR REPLACE TRIGGER tinypki_event_insert_acme_certs
    AFTER INSERT
    ON public.acme_certs
    FOR EACH ROW
    EXECUTE FUNCTION public.tinypki_dispatch_event();

CREATE OR REPLACE TRIGGER tinypki_event_insert_acme_accounts
    AFTER INSERT
    ON public.acme_accounts
    FOR EACH ROW
    EXECUTE FUNCTION public.tinypki_dispatch_event();

CREATE TABLE IF NOT EXISTS public.tinypki_indexer_meta
(
    mkey text COLLATE pg_catalog."default" NOT NULL,
    mvalue json NOT NULL,
    CONSTRAINT tinypki_indexer_meta_pkey PRIMARY KEY (mkey)
);

ALTER TABLE IF EXISTS public.tinypki_indexer_meta
    OWNER to ca;

INSERT INTO public.tinypki_indexer_meta(
	mkey, mvalue)
	VALUES ('initial_sync_state', '{"state": "synced"}');
