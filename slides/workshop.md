class: stage, center, middle

# Password Policy with OpenLDAP
## From basics to production

Ondřej Kuzník, Shawn McKinney

Symas

???

Welcome to the presenter mode. You'll see our notes here and leftovers
suggesting how this was generated.

Keys: P presenter mode (these notes), C clone for the projector, F full screen.

---

# Our roadmap

We start with a common setup, one blanket password policy and evolve from there:

1. [**First contact**](#stage1): log in and look around
2. [**Lockout**](#stage2): crime and punishment
3. [**Slowing attackers**](#stage3) or a slap on the wrist
4. [**Quality**](#stage4) .new[changed in 2.6]: crafting with quality
5. [**Targeted assignment**](#stage5) .new[2.7]: making the policy (assignment) make sense
6. [**Lifecycle and idleness**](#stage6) .new[changed in 2.6]: start, end, how to deal with unused accounts
7. [**Hashing**](#stage7) .new[2.7]: making insecure hashes secure
8. [**...**](#stage8) bonus!
9. [**Closing**](#closing) closing remarks

---

# Follow at your own pace

![image QR Code for https://symas.github.io/ldapcon2026-workshop/](./slides.png)

???

Insert QR code for the slides

This is where we stop and check everyone has the handout, another chance to
resolve people's connection issues (next slide is last chance) and collect
ssh keys

---

# Your server

Log in to your `ldap1` and point the tools at it:

```
export LDAPURI=ldapi:/// LDAPBASE=dc=example,dc=com
```

As root on the socket you are the directory's `rootdn`. Everybody
else's password is `<uid>-pw`: `alice` has `alice-pw`.

Decide now how you will change the configuration, and stay with it
(all solutions are shown both ways):

- **`slapd.conf`**: edit it, restart slapd
- **`cn=config`**: `ldapmodify` as root, takes effect straight away

For `cn=config`, convert once, now (`slapd.d` takes precedence):

```
cd /opt/symas/etc/openldap && mkdir slapd.d
slaptest -f slapd.conf -F slapd.d && chown -R openldap: slapd.d
systemctl restart symas-openldap-server
```

???

ldap1 suggests there are others, yes. These machines are shared between
both workshops so be careful about changing things on machines you haven't
heard about yet or risk making your life harder later.

The machines run slapd straight from slapd.conf until slapd.d exists.
slapd runs as openldap, hence the chown. Convert at the start, not
later: from stage 4 on, slapd.conf has ppolicy_check_module, which does
not survive conversion on this build (BUGS.md #11). Re-running a
playbook rebuild replaces slapd.conf and removes slapd.d, putting the
attendee back on slapd.conf.

---

# The cast

**One rule:** experiment freely but on accounts you create yourself. The below
are set up to illustrate concepts at key times. Entries below are of the form
`uid=<uid>,ou=people,dc=example,dc=com`:

.small[
| `uid`| State | Notes |
|:--|:--|:--|
| `alice` | healthy | the control case |
| `bob` | changed 400 days ago | expired |
| `carol` | changed 345 days ago | about to expire |
| `dave` | not seen for 200 days | idle |
| `erin` | reset by an administrator | must change |
| `frank` | locked by an administrator | |
| `grace` | an administrator | |
| `heidi` | has no password at all | |
| `mallory` | expendable | lock her out as often as you like |
| `peggy` | fresh | for changing passwords |
]

If anything goes wrong, the seed LDIF is stored at
`/var/symas/openldap-data/bootstrap.ldif` on `ldap1`.

???

The full list, services and partners included, is at the top of
data/30-people.ldif.j2. The README has the don't-before table.

---

class: stage, center, middle
name: stage1

# 1. First contact
## What is the server already doing?

???

Nothing gets configured in this stage. It teaches the three moves every
later stage is diagnosed with: ask an entry for its policy, read the
policy, bind with the control.

---

# slapo-ppolicy in one slide

- A **policy** is an ordinary entry with objectClass `pwdPolicy`
- The **overlay** applies one to every bind and password change
- Its **state** lives on the account: `pwdChangedTime`,
  `pwdFailureTime`, `pwdAccountLockedTime`, ...
- .new[2.5] A **password administrator** is an account that has `manage`
  (!= `write`) access to `userPassword`, that **includes** rootdn

What your server starts with:

```
overlay ppolicy
ppolicy_hash_cleartext
ppolicy_default "cn=default,ou=policies,dc=example,dc=com"
```

One policy, and everybody with a password is subject to it.

???

ppolicy_hash_cleartext: a cleartext password arrives, gets hashed on
the way in, and the overlay can check its quality first.

---

# The policy

.small[
| Attribute | Value | Note |
|:--|--:|:--|
| `pwdMaxAge` | 31536000 | expires after a year |
| `pwdExpireWarning` | 2592000 | warned for the last month |
| `pwdMinLength` | 8 | |
| `pwdMaxFailure` | 5 | five wrong guesses... |
| `pwdLockout` | TRUE | ...lock the account... |
| `pwdLockoutDuration` | 300 | ...for five minutes |
| `pwdInHistory` | 3 | no reusing the last three |
| `pwdMustChange` | TRUE | an admin reset must be followed by a change |
]

---

class: task

# Look around

- Which policy applies to `alice`? `pwdPolicySubentry` says; it is
  operational, so ask for it **by name**
- As `alice`, read that policy
- As `alice`, look at `bob`'s `pwdChangedTime`

---

class: check, dense

# Look around

```nohighlight
*$ ldapsearch -x -D uid=alice,ou=people,dc=example,dc=com -w alice-pw \
*    -LLL -s base -b uid=alice,ou=people,dc=example,dc=com pwdPolicySubentry
dn: uid=alice,ou=people,dc=example,dc=com
pwdPolicySubentry: cn=default,ou=policies,dc=example,dc=com
```

```nohighlight
*$ ldapsearch -x -D uid=alice,ou=people,dc=example,dc=com -w alice-pw -LLL \
*    -b cn=default,ou=policies,dc=example,dc=com \
*    pwdMaxAge pwdMaxFailure pwdLockout pwdLockoutDuration
dn: cn=default,ou=policies,dc=example,dc=com
pwdMaxAge: 31536000
pwdMaxFailure: 5
pwdLockout: TRUE
pwdLockoutDuration: 300
```

```nohighlight
*$ ldapsearch -x -D uid=alice,ou=people,dc=example,dc=com -w alice-pw \
*    -LLL -s base -b uid=bob,ou=people,dc=example,dc=com pwdChangedTime
dn: uid=bob,ou=people,dc=example,dc=com
```

The rules are public; how close bob is to a lockout is not.

???

test_an_entry_can_be_asked_which_policy_applies_to_it,
test_the_policy_is_readable_by_anyone_who_is_logged_in,
test_policy_state_is_hidden_from_other_users. pwdPolicySubentry is
computed: nobody set it on alice.

---

# Asking the server why

A failed bind has to say "invalid credentials" and nothing else. Attach the
**password policy control** (`-e ppolicy`) to get more information:

```nohighlight
*$ ldapwhoami -x -e ppolicy -D uid=alice,ou=people,dc=example,dc=com -w alice-pw
dn:uid=alice,ou=people,dc=example,dc=com
*$ ldapwhoami -x -e ppolicy -D uid=bob,ou=people,dc=example,dc=com -w bob-pw
ldap_bind: Invalid credentials (49); Password expired
*$ ldapwhoami -x -e ppolicy -D uid=carol,ou=people,dc=example,dc=com -w carol-pw
ldap_bind: Success (0) (Password expires in [...] seconds)
dn:uid=carol,ou=people,dc=example,dc=com
```

???

test_a_healthy_bind_is_quiet, test_an_expired_password_is_refused,
test_a_warning_arrives_before_expiry. Carol's seconds depend on when
the machines were set up; the lesson is the warning.

---

class: task

# erin can log in, but...

...nothing else works for her. Find out why, and get her going again:
change her password, as erin. Try a short one first.

---

class: check, dense

# erin can log in, but...

```nohighlight
*$ ldapwhoami -x -e ppolicy -D uid=erin,ou=people,dc=example,dc=com -w erin-pw
ldap_bind: Success (0); Password must be changed
dn:uid=erin,ou=people,dc=example,dc=com
*$ ldapsearch -x -e ppolicy -D uid=erin,ou=people,dc=example,dc=com -w erin-pw -LLL -s base 1.1
Insufficient access (50)
Additional information: Operations are restricted to bind/unbind/abandon/StartTLS/modify password
```

```nohighlight
*$ ldappasswd -x -e ppolicy -D uid=erin,ou=people,dc=example,dc=com -w erin-pw -s short
Result: Constraint violation (19)
ppolicy: error=6 (Password is too short for policy)
*$ ldappasswd -x -e ppolicy -D uid=erin,ou=people,dc=example,dc=com -w erin-pw -s Trombone-Marmalade-71
*$ ldapwhoami -x -e ppolicy -D uid=erin,ou=people,dc=example,dc=com -w Trombone-Marmalade-71
dn:uid=erin,ou=people,dc=example,dc=com
```

An administrator reset her password (`pwdReset`) and the policy has
`pwdMustChange`. The change clears it, and stamps the `pwdChangedTime`
that `pwdMaxAge` counts from.

???

test_an_administrative_reset_demands_a_change,
test_a_user_under_reset_cannot_do_anything_else_first,
test_changing_the_password_clears_the_reset,
test_changing_a_password_stamps_pwdChangedTime,
test_the_quality_floor_is_enforced

---

class: stage, center, middle
name: stage2

# 2. Lockout
## Five strikes, and then what?

???

The seed already locks after five failures. This stage makes that
lockout usable: what the client is told, how an account gets unlocked,
how much a failed bind can write, and how a lock ends.

---

# When a Bind fails, things happen

Every wrong password adds a `pwdFailureTime` to the account.

When there are `pwdMaxFailure` of them (5), and the policy has
`pwdLockout: TRUE`, the overlay adds `pwdAccountLockedTime` and the
account is locked: **even the right password is refused.**

A successful bind clears the failures. Nobody else can: they are
`NO-USER-MODIFICATION`, even for an administrator except via a password
reset.

---

class: task

# Lock mallory out

They're flaky and forgetful. Five wrong passwords, look at their entry as an
administrator, then try the right password.

---

class: check, dense

# Lock mallory out

```nohighlight
*$ for i in 1 2 3 4 5; do ldapwhoami -x -D uid=mallory,ou=people,dc=example,dc=com -w guess; done
ldap_bind: Invalid credentials (49)
*$ ldapsearch -Q -Y EXTERNAL -LLL -s base -b uid=mallory,ou=people,dc=example,dc=com \
*    pwdFailureTime pwdAccountLockedTime
dn: uid=mallory,ou=people,dc=example,dc=com
pwdFailureTime: [...]
pwdAccountLockedTime: [...]
```

```nohighlight
*$ ldapwhoami -x -e ppolicy -D uid=mallory,ou=people,dc=example,dc=com -w mallory-pw
ldap_bind: Invalid credentials (49)
```

The right password gets exactly what a wrong one gets. The safe
default: "account locked" also says "this account exists".

???

test_a_wrong_password_is_recorded_in_the_entry,
test_five_failures_lock_the_account,
test_a_locked_account_rejects_the_right_password,
test_but_the_client_is_not_told_why

---

class: task

# Tell them

`ppolicy_use_lockout` makes a locked account say so. Worth it when
your users are real people and "invalid credentials" sends them to the
help desk.

Turn it on, and bind as mallory again.

---

class: solution

# Tell them

In `slapd.conf`, in the ppolicy section, then restart slapd:

```diff
+ppolicy_use_lockout
```

Or live, in `cn=config`:

```nohighlight
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcPPolicyUseLockout
olcPPolicyUseLockout: TRUE
EOF
modifying entry "olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config"
*$ ldapwhoami -x -e ppolicy -D uid=mallory,ou=people,dc=example,dc=com -w mallory-pw
ldap_bind: Invalid credentials (49); Account locked
```

???

test_turning_on_use_lockout_changes_the_answer. Finding the overlay's
DN: ldapsearch -Q -Y EXTERNAL -b cn=config '(olcOverlay=*ppolicy)' dn

---

class: task

# Unlocking

Account unlocks when `pwdAccountLockedTime` lapses or by an administrator
deleting `pwdAccountLockedTime`.

Unlock mallory. Then try `frank`: an administrator locked him.

---

class: solution

# Unlocking

```nohighlight
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: uid=mallory,ou=people,dc=example,dc=com
changetype: modify
delete: pwdAccountLockedTime
EOF
modifying entry "uid=mallory,ou=people,dc=example,dc=com"
*$ ldapwhoami -x -e ppolicy -D uid=mallory,ou=people,dc=example,dc=com -w mallory-pw
dn:uid=mallory,ou=people,dc=example,dc=com
*$ ldapwhoami -x -e ppolicy -D uid=frank,ou=people,dc=example,dc=com -w frank-pw
ldap_bind: Invalid credentials (49); Account locked
```

frank's lock is `000001010000Z`: a special value for "locked by an
administrator". This one never expires.

???

test_an_administrator_unlocks_by_deleting_the_stamp,
test_franks_permanent_lock_does_not_expire

---

class: task

# Bounding it

- **Writes**: every failed bind is a write, and anyone can bind.
  `pwdMaxRecordedFailure` caps the failures kept (but at least
  `pwdMaxFailure`). Set it to 5 on `cn=default`.
- **Time**: `pwdLockoutDuration` (300) ends a lock on its own. Make it
  10 seconds, lock mallory, check `pwdAccountLockedTime`, wait, and put it
  back.

???

pwdFailureCountInterval also exists: old failures stop counting towards
the lock, so slow guessing never trips it.

---

class: check, dense

# Bounding it

```nohighlight
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: cn=default,ou=policies,dc=example,dc=com
changetype: modify
add: pwdMaxRecordedFailure
pwdMaxRecordedFailure: 5
EOF
modifying entry "cn=default,ou=policies,dc=example,dc=com"
```

```nohighlight
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: cn=default,ou=policies,dc=example,dc=com
changetype: modify
replace: pwdLockoutDuration
pwdLockoutDuration: 10
EOF
modifying entry "cn=default,ou=policies,dc=example,dc=com"
*$ for i in 1 2 3 4 5; do ldapwhoami -x -D uid=mallory,ou=people,dc=example,dc=com -w guess; done
*$ ldapwhoami -x -e ppolicy -D uid=mallory,ou=people,dc=example,dc=com -w mallory-pw
ldap_bind: Invalid credentials (49); Account locked
*$ sleep 11
*$ ldapwhoami -x -e ppolicy -D uid=mallory,ou=people,dc=example,dc=com -w mallory-pw
dn:uid=mallory,ou=people,dc=example,dc=com
```

???

test_failures_written_to_an_entry_are_bounded,
test_a_lockout_can_expire_on_its_own

---

class: solution

# Put it back

The rest of the day depends on it:

```nohighlight
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: cn=default,ou=policies,dc=example,dc=com
changetype: modify
replace: pwdLockoutDuration
pwdLockoutDuration: 300
EOF
modifying entry "cn=default,ou=policies,dc=example,dc=com"
```

???

test_leave_a_sane_lockout_duration_behind

---

class: stage, center, middle
name: stage3

# 3. Slowing attackers down
## instead of locking people out

---

# The trouble with lockout

Anyone who knows a username can lock its owner out, at will.

The alternative: make every wrong guess **cost time**.

- `pwdMinDelay`: the wait after a failure, doubling with each one...
- `pwdMaxDelay`: ...up to this
- the wait is stamped as `pwdAccountTmpLockoutEnd`, and until then
  **even the right password is refused**

1, 2, 4, 4, 4 seconds: nothing to a user who mistyped, ruinous for a
guessing attacker.

Note: This "return immediately and force a temporary lockout" is OpenLDAP's
implementation. Others might actually delay the Bind response. Check before
you rely on this.

---

class: task

# A policy that delays

Create `cn=hardened,ou=policies`: one-second minimum delay, four-second
maximum, and never a permanent lock.

Try it on mallory: `pwdPolicySubentry` written on an entry names its
policy, overriding everything else.

---

class: solution, dense

# A policy that delays

```nohighlight
*$ ldapadd -Q -Y EXTERNAL <<EOF
dn: cn=hardened,ou=policies,dc=example,dc=com
objectClass: namedPolicy
objectClass: pwdPolicy
cn: hardened
description: Delay, never lock. See stage 3.
pwdAttribute: userPassword
pwdMaxAge: 31536000
pwdMinLength: 8
pwdLockout: TRUE
pwdMaxFailure: 0
pwdMinDelay: 1
pwdMaxDelay: 4
EOF
adding new entry "cn=hardened,ou=policies,dc=example,dc=com"
```

```nohighlight
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: uid=mallory,ou=people,dc=example,dc=com
changetype: modify
replace: pwdPolicySubentry
pwdPolicySubentry: cn=hardened,ou=policies,dc=example,dc=com
EOF
modifying entry "uid=mallory,ou=people,dc=example,dc=com"
*$ ldapsearch -Q -Y EXTERNAL -LLL -s base -b uid=mallory,ou=people,dc=example,dc=com pwdPolicySubentry
dn: uid=mallory,ou=people,dc=example,dc=com
pwdPolicySubentry: cn=hardened,ou=policies,dc=example,dc=com
```

???

pwdLockout: TRUE because the delay *is* a lockout; pwdMaxFailure: 0 so
it never becomes a real one.

test_create_a_policy_that_delays_instead_of_locking,
test_a_policy_named_on_the_entry_beats_the_rules. Fine for one
account; for ten thousand, see stage 5.

---

class: task

# Guess, and wait

One wrong guess as mallory, then the right password straight away.
Look at her entry; try deleting the stamp as root. Wait two seconds and
try again.

---

class: check, dense

# Guess, and wait

```nohighlight
*$ ldapwhoami -x -e ppolicy -D uid=mallory,ou=people,dc=example,dc=com -w guess
ldap_bind: Invalid credentials (49)
*$ ldapwhoami -x -e ppolicy -D uid=mallory,ou=people,dc=example,dc=com -w mallory-pw
ldap_bind: Invalid credentials (49); Account locked
*$ ldapsearch -Q -Y EXTERNAL -LLL -s base -b uid=mallory,ou=people,dc=example,dc=com pwdAccountTmpLockoutEnd
pwdAccountTmpLockoutEnd: [...]
*$ sleep 2
*$ ldapwhoami -x -e ppolicy -D uid=mallory,ou=people,dc=example,dc=com -w mallory-pw
dn:uid=mallory,ou=people,dc=example,dc=com
```

```nohighlight
*$ ldapwhoami -x -e ppolicy -D uid=mallory,ou=people,dc=example,dc=com -w guess
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: uid=mallory,ou=people,dc=example,dc=com
changetype: modify
delete: pwdAccountTmpLockoutEnd
EOF
ldap_modify: Constraint violation (19)
*$ sleep 2
*$ ldapwhoami -x -e ppolicy -D uid=mallory,ou=people,dc=example,dc=com -w mallory-pw
dn:uid=mallory,ou=people,dc=example,dc=com
```

Nobody can cut a backoff short, not even root: you wait.

???

test_each_failure_costs_twice_the_last, test_the_cap_holds,
test_the_right_password_is_refused_while_the_backoff_runs,
test_nobody_can_clear_a_backoff_early,
test_and_the_password_works_once_it_expires

---

class: solution

# Delays and lockout together

On a policy that also locks, failures below `pwdMaxFailure` are
delayed (rate-limiting attacks) and then it locks out properly.

mallory goes back to the default; `cn=hardened` stays:

```nohighlight
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: uid=mallory,ou=people,dc=example,dc=com
changetype: modify
delete: pwdPolicySubentry
EOF
modifying entry "uid=mallory,ou=people,dc=example,dc=com"
*$ ldapsearch -Q -Y EXTERNAL -LLL -s base -b uid=mallory,ou=people,dc=example,dc=com pwdPolicySubentry
pwdPolicySubentry: cn=default,ou=policies,dc=example,dc=com
```

???

test_delay_and_lockout_compose, test_tidy_up_for_the_next_stage.
A policy with delays keeps at most 5 failures, even without
pwdMaxRecordedFailure.

---

class: stage, center, middle
name: stage4

# 4. Quality
## What counts as a good password?

---

# What the server can check

Only what it can see: `ppolicy_hash_cleartext` lets a client send the
new password in the clear, to be hashed on the way in.

.small[
| Attribute | |
|:--|:--|
| `pwdMinLength` | 8 in the seed |
| `pwdMaxLength` | keeps a megabyte away from the hash; not for quality |
| `pwdInHistory` | password reuse mitigation, the last 3 cannot be reused |
| `pwdMinAge` | makes the reuse mitigation actually work |
| `pwdSafeModify` | the old password must accompany the new |
| `pwdAllowUserChange` | FALSE when a provisioning system owns it, e.g. for services |
| `pwdCheckQuality` | `2`: refuse a password that cannot be checked (pre-hashed?) |
]

???

test_a_password_can_be_too_long, test_history_has_a_finite_length,
test_pwdMinAge_stops_the_history_being_flushed,
test_pwdSafeModify_demands_the_old_password,
test_pwdAllowUserChange_can_take_self_service_away

---

class: task

# Try them

As `peggy`: set a seven-character password; change it properly, and
try to change it back.

As `uid=admin`, write a ready-made hash into her `userPassword`.

---

class: check, dense

# Try them

```nohighlight
*$ ldappasswd -x -e ppolicy -D uid=peggy,ou=people,dc=example,dc=com -w peggy-pw -s Ab1@efg
ppolicy: error=6 (Password is too short for policy)
*$ ldappasswd -x -e ppolicy -D uid=peggy,ou=people,dc=example,dc=com -w peggy-pw -s Interlude-Falcon-33
*$ ldappasswd -x -e ppolicy -D uid=peggy,ou=people,dc=example,dc=com -w Interlude-Falcon-33 -s peggy-pw
Additional info: Password is in history of old passwords
```

```nohighlight
*$ ldapmodify -x -D uid=admin,ou=administrators,dc=example,dc=com -w admin-pw <<EOF
dn: uid=peggy,ou=people,dc=example,dc=com
changetype: modify
replace: userPassword
userPassword: {SSHA}By44dgO7UjY2IXJqEq0nC/1Z1TxS/SnJ
EOF
ldap_modify: Constraint violation (19)
```

The hash is refused under `pwdCheckQuality: 2`. With `1` it goes
through, and a provisioning system can push anything past every rule.

Note: Any password rules are always bypassed by a password administrator!

???

test_a_password_can_be_too_short, test_history_prevents_immediate_reuse,
test_quality_2_refuses_a_password_it_cannot_inspect,
test_quality_1_accepts_what_it_cannot_inspect. The rootdn is exempt
from all of this, which is why it is uid=admin.

---

# A check module: ppm

Anything cleverer than length is a loadable module. OpenLDAP ships
**ppm**: character classes, forbidden characters, no username in the
password.

- `ppolicy_check_module`: load it, for the whole overlay
- `pwdPolicyChecker`: an auxiliary objectClass a policy must have, to...
- `pwdUseCheckModule: TRUE` .new[2.6]: ...use it, and...
- `pwdCheckModuleArg`: ...configure it

.small[
```
minQuality 3           at least 3 of the 4 classes below
checkRDN 1             the uid may not appear in the password
class-upperCase ABCDEFGHIJKLMNOPQRSTUVWXYZ 0 1 0
class-lowerCase abcdefghijklmnopqrstuvwxyz 0 1 0
class-digit 0123456789 0 1 0
class-special <>,?;.:/!%*^$&~"#'{([-|`_@)]=}+ 0 1 0
```
]

---

class: task

# Load ppm

Load `/opt/symas/lib/openldap/ppm.so`, and have `cn=default` use it
with the configuration on the last slide. Then try some passwords as
peggy.

---

class: solution, dense

# Load ppm .new[changed in 2.6]

`slapd.conf` (and restart), or `cn=config`:

```diff
+ppolicy_check_module /opt/symas/lib/openldap/ppm.so
```

```nohighlight
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config
changetype: modify
add: olcPPolicyCheckModule
olcPPolicyCheckModule: /opt/symas/lib/openldap/ppm.so
EOF
modifying entry "olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config"
```

???

test_load_the_check_module

---

class: solution, dense

# ...and use it

Several lines of configuration, so base64 (`base64 -w0 ppm.conf`):

```nohighlight
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: cn=default,ou=policies,dc=example,dc=com
changetype: modify
add: objectClass
objectClass: pwdPolicyChecker
-
add: pwdUseCheckModule
pwdUseCheckModule: TRUE
-
add: pwdCheckModuleArg
pwdCheckModuleArg:: bWluUXVhbGl0eSAzCmNoZWNrUkROIDEKZm9yYmlkZGVuQ2hhcnMKbWF4Q29uc2VjdXRpdmVQZXJDbGFzcyAwCnVzZUNyYWNrbGliIDAKY2xhc3MtdXBwZXJDYXNlIEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaIDAgMSAwCmNsYXNzLWxvd2VyQ2FzZSBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eiAwIDEgMApjbGFzcy1kaWdpdCAwMTIzNDU2Nzg5IDAgMSAwCmNsYXNzLXNwZWNpYWwgPD4sPzsuOi8hJSpeJCZ+IiMneyhbLXxgX0ApXT19KyAwIDEgMAo=
EOF
modifying entry "cn=default,ou=policies,dc=example,dc=com"
```

???

test_a_policy_must_opt_in_to_carrying_a_checker. Switch it off per
policy with pwdUseCheckModule: FALSE. Don't remove olcPPolicyCheckModule
once loaded: on this build that crashes slapd (BUGS.md #11).

---

class: check

# ppm at work

```nohighlight
*$ ldappasswd -x -e ppolicy -D uid=peggy,ou=people,dc=example,dc=com -w Interlude-Falcon-33 -s onlylowercaseletters
Additional info: [...] does not pass required number of strength checks (1 of 3)
*$ ldappasswd -x -e ppolicy -D uid=peggy,ou=people,dc=example,dc=com -w Interlude-Falcon-33 -s Peggy-Is-Here-42
Additional info: [...] contains tokens from the RDN
*$ ldappasswd -x -e ppolicy -D uid=peggy,ou=people,dc=example,dc=com -w Interlude-Falcon-33 -s Thunder-Wallaby-42
*$ ldapwhoami -x -D uid=peggy,ou=people,dc=example,dc=com -w Thunder-Wallaby-42
dn:uid=peggy,ou=people,dc=example,dc=com
```

Too few classes, and her own name: both refused.

???

test_ppm_rejects_a_password_with_too_few_character_classes,
test_ppm_can_refuse_a_password_containing_the_username,
test_ppm_accepts_one_with_enough

---

class: stage, center, middle
name: stage5

# 5. Targeted assignment
## The right policy for each account .new[2.7]

---

class: check

# Something is already broken

The service account `backup` cannot log in. Why?

```nohighlight
*$ ldapwhoami -x -e ppolicy -D uid=backup,ou=applications,dc=example,dc=com -w backup-pw
ldap_bind: Invalid credentials (49); Password expired
*$ ldapsearch -Q -Y EXTERNAL -LLL -s base -b uid=backup,ou=applications,dc=example,dc=com pwdPolicySubentry
pwdPolicySubentry: cn=default,ou=policies,dc=example,dc=com
```

One policy for everybody: the backup agent's password expired like a
person's, an outage at 3am on a Sunday. `web01` and `db01` too.

???

test_the_seed_is_broken_and_this_is_how_you_see_it. Setting
pwdPolicySubentry on each (stage 3) does not scale, and puts the
decision in the data.

---

# ppolicy_rules .new[2.7]

Rules in the configuration pick a policy for each entry:

```
ppolicy_rules dn.subtree="ou=applications,dc=example,dc=com"
              policy_dn="cn=service,ou=policies,dc=example,dc=com"
```

- **where**: `dn.base`, `dn.one`, `dn.subtree`, `dn.regex`
- **what else**: `filter=`, `group/<objectClass>/<attr>=`
- `require_password=` (default yes): skip entries without a password
- **tried in order; the first match wins**, unless its action is
  `continue`
- `pwdPolicySubentry` on the entry still beats them all but this is now
  discouraged

In `cn=config` each rule is an entry below the overlay's, objectClasses
**`olcPPolicyScopedRule`**/**`olcPPolicyRegexRule`**.

???

This should be around the 1h30 mark, if closer to 2h, start cutting.

ITS#9343. The rules come before ppolicy_default, which only catches
what they leave.

---

class: task

# A policy for services

No expiry and **no lockout** since a service account lockout is a denial of
service. Twenty characters minimum, no history.

Create `cn=service`, and send `ou=applications` and `ou=hosts` to it.

---

class: solution, dense

# A policy for services

```nohighlight
*$ ldapadd -Q -Y EXTERNAL <<EOF
dn: cn=service,ou=policies,dc=example,dc=com
objectClass: namedPolicy
objectClass: pwdPolicy
cn: service
description: Service accounts. Never expires, never locks.
pwdAttribute: userPassword
pwdLockout: FALSE
pwdMaxFailure: 0
pwdMinLength: 20
pwdInHistory: 0
EOF
adding new entry "cn=service,ou=policies,dc=example,dc=com"
```

In `slapd.conf`, at the end of the ppolicy section:

```diff
+ppolicy_rules dn.subtree="ou=applications,dc=example,dc=com" policy_dn="cn=service,ou=policies,dc=example,dc=com"
+ppolicy_rules dn.subtree="ou=hosts,dc=example,dc=com" policy_dn="cn=service,ou=policies,dc=example,dc=com"
```

???

test_write_a_policy_that_suits_a_service_account

---

class: solution, dense

# ...or the rules in cn=config

```nohighlight
*$ ldapadd -Q -Y EXTERNAL <<EOF
dn: cn=service,olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config
objectClass: olcPPolicyScopedRule
cn: service
olcPPolicyRuleObject: ou=applications,dc=example,dc=com
olcPPolicyRuleScope: sub
olcPPolicyRulePolicy: cn=service,ou=policies,dc=example,dc=com
olcPPolicyRuleAction: stop

dn: cn=hosts,olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config
objectClass: olcPPolicyScopedRule
cn: hosts
olcPPolicyRuleObject: ou=hosts,dc=example,dc=com
olcPPolicyRuleScope: sub
olcPPolicyRulePolicy: cn=service,ou=policies,dc=example,dc=com
olcPPolicyRuleAction: stop
EOF
adding new entry "cn=service,olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config"
adding new entry "cn=hosts,olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config"
*$ ldapwhoami -x -e ppolicy -D uid=backup,ou=applications,dc=example,dc=com -w backup-pw
dn:uid=backup,ou=applications,dc=example,dc=com
*$ ldapwhoami -x -e ppolicy -D cn=web01,ou=hosts,dc=example,dc=com -w web01-pw
dn:cn=web01,ou=hosts,dc=example,dc=com
```

???

test_the_first_rule_takes_them_off_the_default,
test_and_the_service_accounts_come_back, test_cover_the_machine_accounts_too

---

class: task

# Partners, and the pager

- `ou=external` subtree: 90-day expiry, three strikes and 15 minutes out,
  twelve characters
- members of `cn=oncall` (rfc2307bis `groupOfMembers`, not the default
  `groupOfNames`): 90 days, three strikes, sixteen characters

---

class: solution

# Partners

```nohighlight
*$ ldapadd -Q -Y EXTERNAL <<EOF
dn: cn=external,ou=policies,dc=example,dc=com
objectClass: namedPolicy
objectClass: pwdPolicy
cn: external
description: Partner accounts. Short leash.
pwdAttribute: userPassword
pwdMaxAge: 7776000
pwdLockout: TRUE
pwdMaxFailure: 3
pwdLockoutDuration: 900
pwdMinLength: 12
EOF
adding new entry "cn=external,ou=policies,dc=example,dc=com"
```

---

class: solution

# The pager

```nohighlight
*$ ldapadd -Q -Y EXTERNAL <<EOF
dn: cn=privileged,ou=policies,dc=example,dc=com
objectClass: namedPolicy
objectClass: pwdPolicy
cn: privileged
description: On-call staff. Tighter than ordinary users.
pwdAttribute: userPassword
pwdMaxAge: 7776000
pwdLockout: TRUE
pwdMaxFailure: 3
pwdMinLength: 16
EOF
adding new entry "cn=privileged,ou=policies,dc=example,dc=com"
```

???

test_partners_are_held_to_a_stricter_standard

---

class: solution, dense

# Their rules

```diff
+ppolicy_rules dn.subtree="ou=external,dc=example,dc=com" policy_dn="cn=external,ou=policies,dc=example,dc=com"
+ppolicy_rules dn.subtree="ou=people,dc=example,dc=com" group/groupOfMembers/member="cn=oncall,ou=groups,dc=example,dc=com" policy_dn="cn=privileged,ou=policies,dc=example,dc=com"
```

```nohighlight
*$ ldapadd -Q -Y EXTERNAL <<EOF
dn: cn=external,olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config
objectClass: olcPPolicyScopedRule
cn: external
olcPPolicyRuleObject: ou=external,dc=example,dc=com
olcPPolicyRuleScope: sub
olcPPolicyRulePolicy: cn=external,ou=policies,dc=example,dc=com
olcPPolicyRuleAction: stop

dn: cn=oncall,olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config
objectClass: olcPPolicyScopedRule
cn: oncall
olcPPolicyRuleObject: ou=people,dc=example,dc=com
olcPPolicyRuleScope: sub
olcPPolicyRuleGroup: cn=oncall,ou=groups,dc=example,dc=com
olcPPolicyRuleGroupOC: groupOfMembers
olcPPolicyRuleGroupAttr: member
olcPPolicyRulePolicy: cn=privileged,ou=policies,dc=example,dc=com
olcPPolicyRuleAction: stop
EOF
adding new entry "cn=external,olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config"
adding new entry "cn=oncall,olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config"
```

???

test_a_rule_can_select_on_group_membership

---

class: check

# Who gets what

```nohighlight
*$ ldapsearch -Q -Y EXTERNAL -LLL -s base -b uid=victor,ou=external,dc=example,dc=com pwdPolicySubentry
pwdPolicySubentry: cn=external,ou=policies,dc=example,dc=com
*$ ldapsearch -Q -Y EXTERNAL -LLL -s base -b uid=dave,ou=people,dc=example,dc=com pwdPolicySubentry
pwdPolicySubentry: cn=privileged,ou=policies,dc=example,dc=com
*$ ldapsearch -Q -Y EXTERNAL -LLL -s base -b uid=alice,ou=people,dc=example,dc=com pwdPolicySubentry
pwdPolicySubentry: cn=default,ou=policies,dc=example,dc=com
```

Also worth knowing:

- `filter="(employeeType=contractor)"` matches entries accordingly, only
  stored attributes
- `continue` action type records a match and keeps looking: broad first,
  narrow later
- `dn.regex` + `policy_dn.expand` (or `group.expand`) derives the policy
  (group) from the DN

???

test_a_rule_can_select_on_a_filter,
test_continue_remembers_but_lets_a_later_rule_override,
test_one_regex_rule_can_replace_a_pile_of_scoped_ones. A regex
expanding to a policy that does not exist simply does not match.

---

class: task

# Retire ppolicy_default

It is deprecated. Unless you use action `continue`, best replaced with a
rule at the **end** that catches everything with a password. Nobody's
policy should change, and heidi, who has no password, should still have
none.

From then on, new rules go *before* the catch-all: after it they are
never reached.

???

test_require_password_decides_about_password_less_entries,
test_a_rule_appended_after_the_catch_all_does_nothing

---

class: solution, dense

# Retire ppolicy_default

```diff
-ppolicy_default "cn=default,ou=policies,dc=example,dc=com"
+ppolicy_rules dn.subtree="dc=example,dc=com" require_password=true policy_dn="cn=default,ou=policies,dc=example,dc=com"
```

```nohighlight
*$ ldapadd -Q -Y EXTERNAL <<EOF
dn: cn=default,olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config
objectClass: olcPPolicyScopedRule
cn: default
olcPPolicyRuleObject: dc=example,dc=com
olcPPolicyRuleScope: sub
olcPPolicyRuleRequirePassword: TRUE
olcPPolicyRulePolicy: cn=default,ou=policies,dc=example,dc=com
olcPPolicyRuleAction: stop
EOF
adding new entry "cn=default,olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config"
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config
changetype: modify
delete: olcPPolicyDefault
EOF
modifying entry "olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config"
*$ ldapsearch -Q -Y EXTERNAL -LLL -s base -b uid=alice,ou=people,dc=example,dc=com pwdPolicySubentry
pwdPolicySubentry: cn=default,ou=policies,dc=example,dc=com
*$ ldapsearch -Q -Y EXTERNAL -LLL -s base -b uid=heidi,ou=people,dc=example,dc=com pwdPolicySubentry
dn: uid=heidi,ou=people,dc=example,dc=com
```

???

test_retire_ppolicy_default_for_an_explicit_catch_all,
test_a_cn_config_rule_without_require_password_skips_heidi

---

class: check

# The result

```nohighlight
*$ ldapsearch -Q -Y EXTERNAL -LLL -s one -b olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config \
*    "(objectClass=*)" olcPPolicyRulePolicy
dn: cn={0}service,olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config
olcPPolicyRulePolicy: cn=service,ou=policies,dc=example,dc=com
dn: cn={1}hosts,olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config
olcPPolicyRulePolicy: cn=service,ou=policies,dc=example,dc=com
dn: cn={2}external,olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config
olcPPolicyRulePolicy: cn=external,ou=policies,dc=example,dc=com
dn: cn={3}oncall,olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config
olcPPolicyRulePolicy: cn=privileged,ou=policies,dc=example,dc=com
dn: cn={4}default,olcOverlay={2}ppolicy,olcDatabase={2}mdb,cn=config
olcPPolicyRulePolicy: cn=default,ou=policies,dc=example,dc=com
```

???

test_the_final_order_is_the_deliverable

---

class: stage, center, middle
name: stage6

# 6. Lifecycle and idleness
## Accounts that should not be used, yet or any more

---

# Three ways to say "not this account"

| Attribute | Use case | Effect |
|:--|:--|:--|
| `pwdAccountLockedTime` | a punishment | cleared by an administrator (stage 2) |
| `pwdMaxIdle` | disuse | judged at every bind |
| `pwdStartTime`, `pwdEndTime` | a schedule | known in advance |

They are not interchangeable, a lock/idleness is reset by a password
reset, start/end specify absolute validity (someone left, ...) that
sticks.

---

class: task

# Why can't they log in?

`ivan` and `judy` both have the right password. Find out what is
stopping them, then let ivan start early.

---

class: check, dense

# Why can't they log in?

```nohighlight
*$ ldapwhoami -x -e ppolicy -D uid=ivan,ou=people,dc=example,dc=com -w ivan-pw
ldap_bind: Invalid credentials (49); Account locked
*$ ldapwhoami -x -e ppolicy -D uid=judy,ou=people,dc=example,dc=com -w judy-pw
ldap_bind: Invalid credentials (49); Account locked
*$ ldapsearch -Q -Y EXTERNAL -LLL "(|(uid=ivan)(uid=judy))" pwdStartTime pwdEndTime
dn: uid=ivan,ou=people,dc=example,dc=com
pwdStartTime: [...]
dn: uid=judy,ou=people,dc=example,dc=com
pwdEndTime: [...]
```

```nohighlight
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: uid=ivan,ou=people,dc=example,dc=com
changetype: modify
delete: pwdStartTime
EOF
modifying entry "uid=ivan,ou=people,dc=example,dc=com"
*$ ldapwhoami -x -e ppolicy -D uid=ivan,ou=people,dc=example,dc=com -w ivan-pw
dn:uid=ivan,ou=people,dc=example,dc=com
```

ivan starts next month; judy left last month, her password untouched
and the reason on record: the honest way to disable an account.

???

test_an_account_can_be_dated_into_the_future,
test_an_account_can_be_dated_into_the_past,
test_the_schedule_is_enforced_whatever_the_policy_says,
test_bringing_an_account_back

---

class: task

# Idle accounts .new[2.6]

`pwdMaxIdle` is judged from `pwdLastSuccess`, and nothing writes that
until **lastbind** is on, on the database. That makes every login a
write, so `lastbind-precision` says how stale it may get.

Turn lastbind on (not the overlay, please don't use the overlay
anymore), with a precision of an hour. Then expire the on-call staff
(`cn=privileged`) after 90 days without a login: `dave` last logged in
200 days ago.

???

test_lastbind_is_off_by_default. Idle expiry only works under a policy
with pwdLockout: TRUE (long-standing; BUGS.md #3), which cn=service
deliberately is not.

---

class: solution, dense

# Idle accounts

`slapd.conf`, in the database section (and restart), or `cn=config`:

```diff
+lastbind on
+lastbind-precision 3600
```

```nohighlight
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcLastBind
olcLastBind: TRUE
-
replace: olcLastBindPrecision
olcLastBindPrecision: 3600
EOF
modifying entry "olcDatabase={2}mdb,cn=config"
*$ ldapwhoami -x -e ppolicy -D uid=alice,ou=people,dc=example,dc=com -w alice-pw
dn:uid=alice,ou=people,dc=example,dc=com
*$ ldapsearch -Q -Y EXTERNAL -LLL -s base -b uid=alice,ou=people,dc=example,dc=com pwdLastSuccess
pwdLastSuccess: [...]
```

???

test_turning_lastbind_on, test_lastbind_precision_suppresses_the_write

---

class: check

# Idle accounts

```nohighlight
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: cn=privileged,ou=policies,dc=example,dc=com
changetype: modify
add: pwdMaxIdle
pwdMaxIdle: 7776000
EOF
modifying entry "cn=privileged,ou=policies,dc=example,dc=com"
*$ ldapwhoami -x -e ppolicy -D uid=dave,ou=people,dc=example,dc=com -w dave-pw
ldap_bind: Invalid credentials (49); Account locked
*$ ldapsearch -Q -Y EXTERNAL -LLL -s base -b uid=dave,ou=people,dc=example,dc=com pwdLastSuccess
pwdLastSuccess: [...]
```

???

test_an_idle_account_expires, test_a_recent_login_keeps_an_account_alive

---

class: stage, center, middle
name: stage7

# 7. Hashing
## Better hashes, upgraded as people log in .new[2.7]

---

# What is stored today

```nohighlight
*$ ldapsearch -Q -Y EXTERNAL -LLL -o ldif_wrap=no -s base -b uid=alice,ou=people,dc=example,dc=com userPassword
userPassword:: e1NTSEF9[...]
*$ ldapsearch -Q -Y EXTERNAL -LLL -o ldif_wrap=no -s base -b uid=oscar,ou=people,dc=example,dc=com userPassword
userPassword:: b3NjYXItcHc=
```

`userPassword` is "not printable", so it comes back in base64: `e1NTSEF9`
(= `{SSHA}`), respectable in 2005. And oscar's `b3NjYXItcHc=` (= literally
`oscar-pw` in the clear), there will be one in every directory that has run
long enough unless enforced otherwise.

???

test_what_the_directory_looks_like_today

---

# Two new attributes .new[2.7]

On the `pwdHashingPolicy` objectClass, which a policy has to opt in to:

- **`pwdDefaultHash`**: the scheme for passwords set under this
  policy. Per policy, so people can be expensive to check and service
  accounts, which bind thousands of times a minute, stay cheap
- **`pwdRehashOnBind`**: upgrade a password on its next successful
  simple bind, the only moment the server sees it in the clear

Tip: this works best when coupled with **`pwdMaxIdle`**, by the end of the
idle period you can (almost) guarantee that everyone is either locked out
or migrated.

---

class: task

# Better hashes

- people (`cn=default`) get `{ARGON2}`, services (`cn=service`)
  `{SSHA512}`
- mallory changes her password: what is stored now?
- alice has no reason to change hers: upgrade her the next time she
  logs in

---

class: solution, dense

# Better hashes

```nohighlight
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: cn=default,ou=policies,dc=example,dc=com
changetype: modify
add: objectClass
objectClass: pwdHashingPolicy
-
add: pwdDefaultHash
pwdDefaultHash: {ARGON2}
EOF
modifying entry "cn=default,ou=policies,dc=example,dc=com"
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: cn=service,ou=policies,dc=example,dc=com
changetype: modify
add: objectClass
objectClass: pwdHashingPolicy
-
add: pwdDefaultHash
pwdDefaultHash: {SSHA512}
EOF
modifying entry "cn=service,ou=policies,dc=example,dc=com"
```

???

test_a_policy_must_opt_in_to_choosing_its_own_hash,
test_service_accounts_get_a_cheap_one

---

class: check, dense

# Better hashes

```nohighlight
*$ ldappasswd -x -D uid=mallory,ou=people,dc=example,dc=com -w mallory-pw -s Grapnel-Windlass-42
*$ ldapsearch -Q -Y EXTERNAL -LLL -o ldif_wrap=no -s base -b uid=mallory,ou=people,dc=example,dc=com userPassword
userPassword:: e0FSR09OMn0[...]
```

```nohighlight
*$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: cn=default,ou=policies,dc=example,dc=com
changetype: modify
add: pwdRehashOnBind
pwdRehashOnBind: TRUE
EOF
modifying entry "cn=default,ou=policies,dc=example,dc=com"
*$ ldapwhoami -x -D uid=alice,ou=people,dc=example,dc=com -w alice-pw
dn:uid=alice,ou=people,dc=example,dc=com
*$ ldapsearch -Q -Y EXTERNAL -LLL -o ldif_wrap=no -s base -b uid=alice,ou=people,dc=example,dc=com userPassword
userPassword:: e0FSR09OMn0[...]
```

`e0FSR09OMn0` is `{ARGON2}`. A rehash happens once, and only when possible:
hash schemes don't match, a successful plain bind.

???

test_people_get_an_expensive_hash,
test_a_new_account_is_provisioned_with_the_right_hash,
test_rehash_on_bind_upgrades_her_without_asking,
test_and_it_only_happens_once, test_a_wrong_password_never_triggers_a_rehash

---

class: gotcha

# A rehash currently counts as a password change .new[as of 2.7.1]

It moves `pwdChangedTime`: carol, weeks from expiry, logs in and has a
whole new year without choosing anything. Migrate a directory like this
and everybody's password age is reset.

And oscar's password has expired, so he cannot log in to be rehashed:
a migration suspends expiry first.

???

test_a_rehash_is_half_a_password_change,
test_a_grace_login_can_rehash_its_way_out_of_expiry,
test_a_cleartext_password_is_swept_up_too

BUGS.md #6

---

class: stage, center, middle
name: stage8

# 8. Replication
## A bind is a write

---
class: dense

# There has been a second server all along

Open a second terminal on your **`ldap2`**, set the same `LDAPURI` and
`LDAPBASE`. (Commands for ldap2 have an `ldap2$` prompt.)

```
ldap2$ export LDAPURI=ldapi:/// LDAPBASE=dc=example,dc=com
```

```nohighlight
*ldap2$ ldapsearch -Q -Y EXTERNAL -LLL -b cn=config "(olcUpdateRef=*)" olcUpdateRef
olcUpdateRef: [...]
*ldap2$ ldapsearch -x -D uid=admin,ou=administrators,dc=example,dc=com -w admin-pw -LLL -s base -b uid=mallory,ou=people,dc=example,dc=com uid
dn: uid=mallory,ou=people,dc=example,dc=com
```

A read-only replica of ldap1; anything that would write here is
referred to that URL. You want to keep it:

```
export PROVIDER=ldaps://ldap1.example.net/    # your olcUpdateRef, exactly
```

Again for `cn=config`, convert first:

```
ldap2$ cd /opt/symas/etc/openldap && mkdir slapd.d
ldap2$ slaptest -f slapd.conf -F slapd.d && chown -R openldap: slapd.d
ldap2$ systemctl restart symas-openldap-server
```

???

Somehow going from slapd.conf's cn=config (without conversion), the below DNs
didn't match? Insist that people convert if they're using cn=config even if we
want to save time.

---

class: check

# Guess against the replica

A failed bind is a write, and a replica is read-only. Guess mallory's
password on ldap2: what does ldap1 know about it?

```nohighlight
*ldap2$ for i in 1 2; do ldapwhoami -x -D uid=mallory,ou=people,dc=example,dc=com -w guess; done
ldap_bind: Invalid credentials (49)
*$ ldapsearch -Q -Y EXTERNAL -LLL -s base -b uid=mallory,ou=people,dc=example,dc=com pwdFailureTime
dn: uid=mallory,ou=people,dc=example,dc=com
```

Nothing. Spread the guesses over the replicas and you get free guesses.

???

test_without_forward_updates_the_replica_keeps_it_to_itself

---

class: task

# Fix it

**In this set up configuration does not replicate.** The policy entries
replicated from ldap1 but ldap2's ppolicy configuration is still the same
as it was 2 hours ago. Adjust these to match ldap1: rules, lockout
disclosure, ppm, lastbind.

Then send the writes upstream. Three settings that only work together:

- **`updateref`**: where to find the writable copy is (already set up)
- **`overlay chain`**: follows that referral instead of returning it,
  as `uid=updater` (ldap1's ACLs already let it write policy state)
- **`ppolicy_forward_updates`**: let ppolicy use it for its own writes

???

test_the_replica_picks_the_same_policy_for_everyone. The updater needs
manage on ldap1's state attributes, since they are NO-USER-MODIFICATION.

---

class: solution, dense

# Fix it, in slapd.conf

On ldap2 (`lastbind` in the database section). `slapd.conf` does not
expand `$PROVIDER`: type your ldap1's URL.

```diff
-ppolicy_default "cn=default,ou=policies,dc=example,dc=com"
+ppolicy_use_lockout
+ppolicy_check_module /opt/symas/lib/openldap/ppm.so
+ppolicy_rules dn.subtree="ou=applications,dc=example,dc=com" policy_dn="cn=service,ou=policies,dc=example,dc=com"
+ppolicy_rules dn.subtree="ou=hosts,dc=example,dc=com" policy_dn="cn=service,ou=policies,dc=example,dc=com"
+ppolicy_rules dn.subtree="ou=external,dc=example,dc=com" policy_dn="cn=external,ou=policies,dc=example,dc=com"
+ppolicy_rules dn.subtree="ou=people,dc=example,dc=com" group/groupOfMembers/member="cn=oncall,ou=groups,dc=example,dc=com" policy_dn="cn=privileged,ou=policies,dc=example,dc=com"
+ppolicy_rules dn.subtree="dc=example,dc=com" require_password=true policy_dn="cn=default,ou=policies,dc=example,dc=com"
+lastbind on
+lastbind-precision 3600
```

```diff
@@ before moduleload
+moduleload back_ldap
@@ before database
+overlay chain
+chain-uri "$PROVIDER"
+chain-idassert-bind bindmethod=simple binddn="uid=updater,ou=administrators,dc=example,dc=com" credentials="updater-pw" mode=none tls_reqcert=demand tls_cacertdir=/etc/ssl/certs/
+chain-return-error TRUE
@@ before ppolicy_rules
+ppolicy_forward_updates
```

---

class: solution, dense

# Fix it, in cn=config (#1/5)

On ldap2 the overlay is `olcOverlay={0}ppolicy,olcDatabase={1}mdb`:
different numbers from ldap1's.

```nohighlight
*ldap2$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcPPolicyUseLockout
olcPPolicyUseLockout: TRUE
-
add: olcPPolicyCheckModule
olcPPolicyCheckModule: /opt/symas/lib/openldap/ppm.so
-
delete: olcPPolicyDefault

dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcLastBind
olcLastBind: TRUE
-
replace: olcLastBindPrecision
olcLastBindPrecision: 3600
EOF
modifying entry "olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config"
modifying entry "olcDatabase={1}mdb,cn=config"
```

---

class: solution, dense

# Fix it, in cn=config: the rules (#2/5)

```nohighlight
*ldap2$ ldapadd -Q -Y EXTERNAL <<EOF
dn: cn=service,olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config
objectClass: olcPPolicyScopedRule
cn: service
olcPPolicyRuleObject: ou=applications,dc=example,dc=com
olcPPolicyRuleScope: sub
olcPPolicyRulePolicy: cn=service,ou=policies,dc=example,dc=com
olcPPolicyRuleAction: stop

dn: cn=hosts,olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config
objectClass: olcPPolicyScopedRule
cn: hosts
olcPPolicyRuleObject: ou=hosts,dc=example,dc=com
olcPPolicyRuleScope: sub
olcPPolicyRulePolicy: cn=service,ou=policies,dc=example,dc=com
olcPPolicyRuleAction: stop

dn: cn=external,olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config
objectClass: olcPPolicyScopedRule
cn: external
olcPPolicyRuleObject: ou=external,dc=example,dc=com
olcPPolicyRuleScope: sub
olcPPolicyRulePolicy: cn=external,ou=policies,dc=example,dc=com
olcPPolicyRuleAction: stop
EOF
adding new entry "cn=service,olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config"
adding new entry "cn=hosts,olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config"
adding new entry "cn=external,olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config"
```

---

class: solution, dense

# Fix it, in cn=config: the rules (#3/5)

```nohighlight
*ldap2$ ldapadd -Q -Y EXTERNAL <<EOF
dn: cn=oncall,olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config
objectClass: olcPPolicyScopedRule
cn: oncall
olcPPolicyRuleObject: ou=people,dc=example,dc=com
olcPPolicyRuleScope: sub
olcPPolicyRuleGroup: cn=oncall,ou=groups,dc=example,dc=com
olcPPolicyRuleGroupOC: groupOfMembers
olcPPolicyRuleGroupAttr: member
olcPPolicyRulePolicy: cn=privileged,ou=policies,dc=example,dc=com
olcPPolicyRuleAction: stop

dn: cn=default,olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config
objectClass: olcPPolicyScopedRule
cn: default
olcPPolicyRuleObject: dc=example,dc=com
olcPPolicyRuleScope: sub
olcPPolicyRuleRequirePassword: TRUE
olcPPolicyRulePolicy: cn=default,ou=policies,dc=example,dc=com
olcPPolicyRuleAction: stop
EOF
adding new entry "cn=oncall,olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config"
adding new entry "cn=default,olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config"
*ldap2$ ldapsearch -Q -Y EXTERNAL -LLL -s base -b uid=backup,ou=applications,dc=example,dc=com pwdPolicySubentry
pwdPolicySubentry: cn=service,ou=policies,dc=example,dc=com
```

---

class: solution, dense

# Fix it, in cn=config: the chain (#4/5)

```nohighlight
*ldap2$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: cn=module{0},cn=config
changetype: modify
add: olcModuleLoad
olcModuleLoad: back_ldap
EOF
modifying entry "cn=module{0},cn=config"
```

```nohighlight
*ldap2$ ldapadd -Q -Y EXTERNAL <<EOF
dn: olcOverlay=chain,olcDatabase={-1}frontend,cn=config
objectClass: olcOverlayConfig
objectClass: olcChainConfig
olcOverlay: chain
olcChainReturnError: TRUE

dn: olcDatabase=ldap,olcOverlay={0}chain,olcDatabase={-1}frontend,cn=config
objectClass: olcLDAPConfig
objectClass: olcChainDatabase
olcDatabase: ldap
EOF
adding new entry "olcOverlay=chain,olcDatabase={-1}frontend,cn=config"
adding new entry "olcDatabase=ldap,olcOverlay={0}chain,olcDatabase={-1}frontend,cn=config"
```

---

class: solution, dense

# Fix it, in cn=config: the chain (#5/5)

```nohighlight
*ldap2$ ldapadd -Q -Y EXTERNAL <<EOF
dn: olcDatabase=ldap,olcOverlay={0}chain,olcDatabase={-1}frontend,cn=config
objectClass: olcLDAPConfig
objectClass: olcChainDatabase
olcDatabase: ldap
olcDbURI: "$PROVIDER"
olcDbIDAssertBind: bindmethod=simple
  binddn="uid=updater,ou=administrators,dc=example,dc=com"
  credentials="updater-pw" mode=none
  tls_reqcert=demand tls_cacertdir=/etc/ssl/certs/
EOF
adding new entry "olcDatabase=ldap,olcOverlay={0}chain,olcDatabase={-1}frontend,cn=config"
```

```nohighlight
*ldap2$ ldapmodify -Q -Y EXTERNAL <<EOF
dn: olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcPPolicyForwardUpdates
olcPPolicyForwardUpdates: TRUE
EOF
modifying entry "olcOverlay={0}ppolicy,olcDatabase={1}mdb,cn=config"
```

---

class: check

# Relevant information is flowing again

```nohighlight
*ldap2$ ldapwhoami -x -D uid=mallory,ou=people,dc=example,dc=com -w guess
ldap_bind: Invalid credentials (49)
*$ ldapsearch -Q -Y EXTERNAL -LLL -s base -b uid=mallory,ou=people,dc=example,dc=com pwdFailureTime
pwdFailureTime: [...]
*ldap2$ ldapwhoami -x -D uid=alice,ou=people,dc=example,dc=com -w alice-pw
dn:uid=alice,ou=people,dc=example,dc=com
*$ ldapsearch -Q -Y EXTERNAL -LLL -s base -b uid=alice,ou=people,dc=example,dc=com pwdLastSuccess
pwdLastSuccess: [...]
```

A failure on ldap2 is recorded on ldap1, and a login on ldap2 keeps an
account from looking idle (stage 6).

???

test_a_failed_bind_on_the_replica_is_recorded_on_the_provider,
test_guessing_against_the_replica_still_locks_the_account,
test_a_login_on_the_replica_counts_as_activity_on_the_provider,
test_disable_write_stops_the_replica_recording_anything

---

class: stage, center, middle

# That's it

## You've learned how to turn most requirements you'll see into a workable setup

In principle (there is no HA in this example), this is close to what you
would see in a production directory environment that is easy to manage and
audit while allowing replicas at each site.

---

name: closing

# Thank you for attending!

Useful links:

- `man slapo-ppolicy`: https://openldap.org/software/man.cgi?query=slapo-ppolicy
- Relevant UK NCSC guidance: https://www.ncsc.gov.uk/collection/passwords

Also note that sometimes passwords are discouraged, talk to us about OpenLDAP
and OAuth2/OIDC.

???

Also mention:

- getting rid of passwords is better of course (certs, passkeys, OAuth), hence
  the subtle link to the guidance
- OAuth/OIDC with OpenLDAP can happen if someone is willing to fund it, talk to
  us or email sales@symas.com
