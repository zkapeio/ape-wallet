import pytest
from ape import Contract


def test_check_account(factory, new_account):

    assert factory.is_account(new_account), "account is not active"

    zero_address = "0x0000000000000000000000000000000000000000"

    account_contract = Contract(new_account)
    print(new_account)
    assert account_contract.owner() != zero_address