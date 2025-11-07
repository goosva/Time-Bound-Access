import pandas as pd
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import time

@dataclass # Token Class
class Token:
    user: str
    resource: str
    permissions: list
    duration: int  # in seconds
    expires_at: datetime = field(init=False)  # Expiration time calculated at initialization

    def __post_init__(self):
        self.expires_at = datetime.now() + timedelta(seconds=self.duration) # set expiration time
    
    def active(self) -> bool: # returns True if token is still valid
        return datetime.now() < self.expires_at # Check if current time is before expiration time



# Original Policies and Rules Database
#    Name   Resource01    Resource02    Resource03
# 0  Alice   [r, w, e]       []            []
# 1  Bob       []          [r, w, e]       []
# 2  Caleb     []            []          [r, w, e]
ground_rules = {
    "Name"             : ["Alice", "Bob", "Caleb"],
    "Project Alpha"    : [["r", "w", "e"], [], []],
    "Project Beta"     : [[], ["r", "w", "e"], []],
    "Project Charlie": [[], [], ["r", "w", "e"]]
}
df_rules = pd.DataFrame(ground_rules)
#print(df_rules)





# has_permission helper function
# returns true if token exists
def has_token(token):
    if not token:
        return False
    elif token and token.active():
        return True
    else:
        return False


# Returns OG DB Perm Bool AND Token Perm Bool
# Given Requested User, resource at hand, and permission(s) wanting to carry out + Has Token Bool Val
# Get row:    Alice:  []  []  [r, w, e]
# Check if permission available for specific resource in OG DB or token DB
# First Bool is TRUE -> If perm are present for OG DB resource
# Second Bool is TRUE -> If has Token True
# Else, return false, false
def has_permission(user, resource, permission, tok):
    row = df_rules[df_rules["Name"] == user]          # Get User's specific row
    if row.empty or resource not in df_rules.columns:
        return False, False

    perm = row.iloc[0][resource]                      # Get permissions for User at specific resource
    has_tok = has_token(tok)
    # check if token access first
    if has_tok:
        if user != tok.user:
            return False, False
        if resource != tok.resource:
            return False, False

        tok_perms = tok.permissions
        if not tok_perms: # empty token list
            return False, False

        elif set(permission).issubset(tok_perms): # requested perms are in token permissions
            return False, True

        else: # Requested perms not at tok DB resource
            return False, False
    else:
        if not perm: # empty list of perms at OG DB
            return False, False

        elif set(permission).issubset(perm): # permission exists in OG DB
            return True, False

        else:
            return False, False


# NOT CORRECT NEEDS MODIFICATION
# Prints and Notifies user if they have specific permission for specific resource
def policy_notifier(original_decision,tok_decision, user, resource, permission, token):
    perm_list =[]
    for perm in permission:
        if perm == 'r':
            perm_list.append('read')
        if perm == 'w':
            perm_list.append('modify')
        if perm == 'e':
            perm_list.append('execute')

    if tok_decision: # token has correct permissions
        remaining = int((token.expires_at - datetime.now()).total_seconds())
        return f"{user} can temporarily {', '.join(perm_list)} {resource} for {remaining} seconds."

    elif original_decision: # user has correct original permissions
        return f"{user} can {', '.join(perm_list)} {resource}."
    else: # no token, no original permissions
        return f"{user} cannot {', '.join(perm_list)} {resource}. {user} will need a token to access."


def access(user, resource, perm, tok):
        original_check, tok_check = has_permission(user, resource, perm, tok)
        decision = policy_notifier(original_check, tok_check, user, resource, perm, tok)
        return decision




#####################################################
###################### DEMO #########################
#####################################################

user = 'Alice'
res_1 = 'Project Alpha'
res_2 = 'Project Beta'
perm = ['r']
tok = None

original_perm_success = access(user, res_1, perm, tok)
no_tok_reject =         access(user, res_2, perm, tok)
print("Original Request:                ", original_perm_success)
time.sleep(3) # just to give time to show printing ^^^
print("Denial with no Token:            ",no_tok_reject,'\n')
time.sleep(3) # just to give time to show printing ^^^
tok = Token(user='Alice', resource='Project Beta', permissions=['r'], duration=5) # GENERATE TOKEN

tok_success =           access(user, res_2, perm, tok)
print("Success with token:              ",tok_success,'\n')
time.sleep(5) # PAUSE CODE

tok_expire_reject =     access(user, res_2, perm, tok)
print("Denial after token expiration:   ", tok_expire_reject)