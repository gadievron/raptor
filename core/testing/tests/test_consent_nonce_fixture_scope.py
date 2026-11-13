"""Fixed nonce collision fixtures leave unrelated secret generation intact."""
from contextlib import nullcontext
import secrets

import pytest

from packages.exploitability_validation.tests import test_trust_consent as native


@pytest.mark.parametrize('method', [
    'test_rewritten_slot_relocation_denies_under_fixed_nonce',
    'test_verbatim_copy_denies_under_fixed_nonce',
])
@pytest.mark.parametrize('failure', [None, RuntimeError, KeyboardInterrupt],
                         ids=['normal', 'error', 'interrupt'])
def test_actual_fixed_nonce_restores_generator(tmp_path, method, failure):
    namespace = native.tc.secrets
    token_hex = secrets.token_hex
    persist = native.tc.persist_consent
    helper = native.patch_module_attribute
    entered, nonces, verified = [], [], []

    def checked(patch, consumer, binding, name, value):
        assert consumer is native.tc
        assert (binding, name) == ('secrets', 'token_hex')

        def observed(n=16):
            nonces.append(n)
            return value(n)

        private = helper(patch, consumer, binding, name, observed)
        entered.append(private)
        assert secrets.token_hex is token_hex
        return private

    def persisted(output, **kwargs):
        path = persist(output, **kwargs)
        assert path is not None and path.exists()
        # Verify the existing native grant/denial before relocation tampers it.
        record = native.tc.load_consent(output)
        assert record == native.tc.ConsentRecord(kwargs['dynamic'], kwargs['build'])
        state = native.tc._read_mint_state(native.tc._slot_binding(output))
        assert state.present and state.nonce == 'ab' * 16
        verified.append(record)
        assert secrets.token_hex is token_hex
        return path

    expected = pytest.raises(failure, match='owned body failure') if failure else nullcontext()
    with pytest.MonkeyPatch.context() as owner:
        owner.setattr(native, 'patch_module_attribute', checked)
        with expected:
            with pytest.MonkeyPatch.context() as body:
                body.setenv('XDG_DATA_HOME', str(tmp_path / 'keys'))
                body.setattr(native.tc, 'persist_consent', persisted)
                case = native.TestSlotBindingUnderFixedNonce()
                case._fixed_nonce.__wrapped__(case, body)
                run = native.run_dir.__wrapped__(tmp_path)
                getattr(case, method)(tmp_path, run)
                assert len(entered) == 1
                assert nonces == [16, 16]
                assert verified == [native.tc.ConsentRecord(True, True),
                                    native.tc.ConsentRecord(False, None)]
                assert secrets.token_hex is token_hex
                if failure:
                    raise failure('owned body failure')
        assert native.tc.secrets is namespace
        assert native.tc.persist_consent is persist
        assert secrets.token_hex is token_hex
    assert native.patch_module_attribute is helper
