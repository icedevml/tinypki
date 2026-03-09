\c stepca

--
-- Name: acme_account_orders_index; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.acme_account_orders_index (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT acme_account_orders_index_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.acme_account_orders_index OWNER TO ca;

--
-- Name: acme_accounts; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.acme_accounts (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT acme_accounts_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.acme_accounts OWNER TO ca;

--
-- Name: acme_authzs; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.acme_authzs (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT acme_authzs_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.acme_authzs OWNER TO ca;

--
-- Name: acme_certs; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.acme_certs (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT acme_certs_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.acme_certs OWNER TO ca;

--
-- Name: acme_challenges; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.acme_challenges (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT acme_challenges_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.acme_challenges OWNER TO ca;

--
-- Name: acme_external_account_keyID_provisionerID_index; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public."acme_external_account_keyID_provisionerID_index" (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT "acme_external_account_keyID_provisionerID_index_nkey_check" CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public."acme_external_account_keyID_provisionerID_index" OWNER TO ca;

--
-- Name: acme_external_account_keyID_reference_index; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public."acme_external_account_keyID_reference_index" (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT "acme_external_account_keyID_reference_index_nkey_check" CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public."acme_external_account_keyID_reference_index" OWNER TO ca;

--
-- Name: acme_external_account_keys; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.acme_external_account_keys (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT acme_external_account_keys_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.acme_external_account_keys OWNER TO ca;

--
-- Name: acme_keyID_accountID_index; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public."acme_keyID_accountID_index" (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT "acme_keyID_accountID_index_nkey_check" CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public."acme_keyID_accountID_index" OWNER TO ca;

--
-- Name: acme_orders; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.acme_orders (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT acme_orders_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.acme_orders OWNER TO ca;

--
-- Name: acme_serial_certs_index; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.acme_serial_certs_index (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT acme_serial_certs_index_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.acme_serial_certs_index OWNER TO ca;

--
-- Name: admins; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.admins (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT admins_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.admins OWNER TO ca;

--
-- Name: authority_policies; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.authority_policies (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT authority_policies_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.authority_policies OWNER TO ca;

--
-- Name: nonces; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.nonces (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT nonces_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.nonces OWNER TO ca;

--
-- Name: provisioners; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.provisioners (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT provisioners_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.provisioners OWNER TO ca;

--
-- Name: revoked_ssh_certs; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.revoked_ssh_certs (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT revoked_ssh_certs_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.revoked_ssh_certs OWNER TO ca;

--
-- Name: revoked_x509_certs; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.revoked_x509_certs (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT revoked_x509_certs_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.revoked_x509_certs OWNER TO ca;

--
-- Name: ssh_certs; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.ssh_certs (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT ssh_certs_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.ssh_certs OWNER TO ca;

--
-- Name: ssh_host_principals; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.ssh_host_principals (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT ssh_host_principals_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.ssh_host_principals OWNER TO ca;

--
-- Name: ssh_hosts; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.ssh_hosts (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT ssh_hosts_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.ssh_hosts OWNER TO ca;

--
-- Name: ssh_users; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.ssh_users (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT ssh_users_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.ssh_users OWNER TO ca;

--
-- Name: used_ott; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.used_ott (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT used_ott_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.used_ott OWNER TO ca;

--
-- Name: wire_acme_dpop_token; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.wire_acme_dpop_token (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT wire_acme_dpop_token_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.wire_acme_dpop_token OWNER TO ca;

--
-- Name: wire_acme_oidc_token; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.wire_acme_oidc_token (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT wire_acme_oidc_token_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.wire_acme_oidc_token OWNER TO ca;

--
-- Name: x509_certs; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.x509_certs (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT x509_certs_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.x509_certs OWNER TO ca;

--
-- Name: x509_certs_data; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.x509_certs_data (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT x509_certs_data_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.x509_certs_data OWNER TO ca;

--
-- Name: x509_crl; Type: TABLE; Schema: public; Owner: ca
--

CREATE TABLE public.x509_crl (
    nkey bytea NOT NULL,
    nvalue bytea,
    CONSTRAINT x509_crl_nkey_check CHECK ((octet_length(nkey) <= 255))
);


ALTER TABLE public.x509_crl OWNER TO ca;


--
-- Name: acme_account_orders_index acme_account_orders_index_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.acme_account_orders_index
    ADD CONSTRAINT acme_account_orders_index_pkey PRIMARY KEY (nkey);


--
-- Name: acme_accounts acme_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.acme_accounts
    ADD CONSTRAINT acme_accounts_pkey PRIMARY KEY (nkey);


--
-- Name: acme_authzs acme_authzs_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.acme_authzs
    ADD CONSTRAINT acme_authzs_pkey PRIMARY KEY (nkey);


--
-- Name: acme_certs acme_certs_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.acme_certs
    ADD CONSTRAINT acme_certs_pkey PRIMARY KEY (nkey);


--
-- Name: acme_challenges acme_challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.acme_challenges
    ADD CONSTRAINT acme_challenges_pkey PRIMARY KEY (nkey);


--
-- Name: acme_external_account_keyID_provisionerID_index acme_external_account_keyID_provisionerID_index_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public."acme_external_account_keyID_provisionerID_index"
    ADD CONSTRAINT "acme_external_account_keyID_provisionerID_index_pkey" PRIMARY KEY (nkey);


--
-- Name: acme_external_account_keyID_reference_index acme_external_account_keyID_reference_index_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public."acme_external_account_keyID_reference_index"
    ADD CONSTRAINT "acme_external_account_keyID_reference_index_pkey" PRIMARY KEY (nkey);


--
-- Name: acme_external_account_keys acme_external_account_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.acme_external_account_keys
    ADD CONSTRAINT acme_external_account_keys_pkey PRIMARY KEY (nkey);


--
-- Name: acme_keyID_accountID_index acme_keyID_accountID_index_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public."acme_keyID_accountID_index"
    ADD CONSTRAINT "acme_keyID_accountID_index_pkey" PRIMARY KEY (nkey);


--
-- Name: acme_orders acme_orders_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.acme_orders
    ADD CONSTRAINT acme_orders_pkey PRIMARY KEY (nkey);


--
-- Name: acme_serial_certs_index acme_serial_certs_index_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.acme_serial_certs_index
    ADD CONSTRAINT acme_serial_certs_index_pkey PRIMARY KEY (nkey);


--
-- Name: admins admins_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.admins
    ADD CONSTRAINT admins_pkey PRIMARY KEY (nkey);


--
-- Name: authority_policies authority_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.authority_policies
    ADD CONSTRAINT authority_policies_pkey PRIMARY KEY (nkey);


--
-- Name: nonces nonces_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.nonces
    ADD CONSTRAINT nonces_pkey PRIMARY KEY (nkey);


--
-- Name: provisioners provisioners_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.provisioners
    ADD CONSTRAINT provisioners_pkey PRIMARY KEY (nkey);


--
-- Name: revoked_ssh_certs revoked_ssh_certs_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.revoked_ssh_certs
    ADD CONSTRAINT revoked_ssh_certs_pkey PRIMARY KEY (nkey);


--
-- Name: revoked_x509_certs revoked_x509_certs_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.revoked_x509_certs
    ADD CONSTRAINT revoked_x509_certs_pkey PRIMARY KEY (nkey);


--
-- Name: ssh_certs ssh_certs_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.ssh_certs
    ADD CONSTRAINT ssh_certs_pkey PRIMARY KEY (nkey);


--
-- Name: ssh_host_principals ssh_host_principals_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.ssh_host_principals
    ADD CONSTRAINT ssh_host_principals_pkey PRIMARY KEY (nkey);


--
-- Name: ssh_hosts ssh_hosts_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.ssh_hosts
    ADD CONSTRAINT ssh_hosts_pkey PRIMARY KEY (nkey);


--
-- Name: ssh_users ssh_users_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.ssh_users
    ADD CONSTRAINT ssh_users_pkey PRIMARY KEY (nkey);


--
-- Name: used_ott used_ott_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.used_ott
    ADD CONSTRAINT used_ott_pkey PRIMARY KEY (nkey);


--
-- Name: wire_acme_dpop_token wire_acme_dpop_token_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.wire_acme_dpop_token
    ADD CONSTRAINT wire_acme_dpop_token_pkey PRIMARY KEY (nkey);


--
-- Name: wire_acme_oidc_token wire_acme_oidc_token_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.wire_acme_oidc_token
    ADD CONSTRAINT wire_acme_oidc_token_pkey PRIMARY KEY (nkey);


--
-- Name: x509_certs_data x509_certs_data_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.x509_certs_data
    ADD CONSTRAINT x509_certs_data_pkey PRIMARY KEY (nkey);


--
-- Name: x509_certs x509_certs_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.x509_certs
    ADD CONSTRAINT x509_certs_pkey PRIMARY KEY (nkey);


--
-- Name: x509_crl x509_crl_pkey; Type: CONSTRAINT; Schema: public; Owner: ca
--

ALTER TABLE ONLY public.x509_crl
    ADD CONSTRAINT x509_crl_pkey PRIMARY KEY (nkey);

