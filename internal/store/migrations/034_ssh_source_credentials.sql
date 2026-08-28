ALTER TABLE source_credentials DROP CONSTRAINT source_credentials_kind_check;
ALTER TABLE source_credentials ADD CONSTRAINT source_credentials_kind_check
    CHECK (kind IN ('git','git-ssh','registry'));
