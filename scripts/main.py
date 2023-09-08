from ape import accounts, project
from ape.cli import get_user_selected_account
import time

def main():
    account = get_user_selected_account()
    # acc = account.deploy(project.ApeAccount)

    # sig = account.deploy(project.SignatureChecker)
    
    # recovery_period = 86400
    # lock_period = 172800
    # security_period = 86400

    # sec = account.deploy(project.SecurityManager, recovery_period, lock_period, security_period)
    # fac = account.deploy(project.ApeFactory, acc, refund, sig, sec)

    # proxy = account.deploy(project.AccountsProxy, sec)
    # oracle = account.deploy(project.OracleManager)

    # t = int(time.time())
    # base = account.deploy(project.BaseManager, account, t, proxy, oracle)

    # account.deploy(project.ERC20)
    fund = "0xfD77B1D4ACAE0297D05D93fb2a5395A7577901A9"

    account.deploy(project.demo)