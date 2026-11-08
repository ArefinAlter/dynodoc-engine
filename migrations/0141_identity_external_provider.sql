-- A provider link belongs to the provider that made it (security review of main 362d4b1,
-- finding 1). An account was found by (issuer, subject) alone, so an organisation that set up a
-- SAML provider claiming another identity provider's entity ID, with its own signing
-- certificate, could sign in every account that provider had linked. The link key is now
-- (provider, provider_row, issuer, subject): `provider_row` is the organisation's provider row
-- (migration 0077) and null for an operator's provider (OIDC_PROVIDERS_FILE,
-- SAML_PROVIDERS_FILE). Deleting an organisation's provider deletes its links, so a provider made
-- later under the same short name starts with none.
--
-- Existing links: one goes to the organisation's provider with its short name only when that
-- provider names the link's issuer (its OIDC issuer, or a SAML metadata document that contains
-- the entity ID). The rest stay the operator's (an operator file wins over a database provider
-- with the same id, so such links were made by the operator's provider). A link put on the wrong
-- side matches no sign-in and fails closed: the person is linked again under the provider's
-- policy, or not at all.
alter table identity_external
    add column provider_row uuid references organisation_sign_in_provider(id) on delete cascade;
update identity_external e set provider_row = p.id
    from organisation_sign_in_provider p
    where p.slug = e.provider
      and case p.kind
          when 'oidc' then p.settings->>'issuer' = e.issuer
          else strpos(coalesce(p.settings->>'idp_metadata', ''), e.issuer) > 0
      end;
alter table identity_external drop constraint identity_external_issuer_subject_key;
alter table identity_external add constraint identity_external_provider_issuer_subject_key
    unique nulls not distinct (provider, provider_row, issuer, subject);
create index identity_external_provider_row_idx on identity_external(provider_row)
    where provider_row is not null;
