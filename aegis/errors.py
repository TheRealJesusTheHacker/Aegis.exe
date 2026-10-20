"""User-facing errors for Aegis.

Every error in this module speaks plain language. When one of these
is shown to a person, its text is the whole message: what happened
and what to do next, with no technical vocabulary and no internals.
"""


class AegisError(Exception):
    """Base class for all Aegis errors.

    ``user_message`` is the plain-language text shown to the user.
    ``str(error)`` returns that text. A specific message may be
    passed to the constructor to override the class default.
    """

    user_message = "Something went wrong with this vault. Please try again."

    def __init__(self, message=None):
        if message is None:
            message = type(self).user_message
        self.user_message = message
        super().__init__(message)

    def __str__(self):
        return self.user_message


class VaultFormatError(AegisError):
    """The file on disk is not a vault this copy of Aegis can open."""

    user_message = (
        "This file isn't a vault Aegis can open — it may be damaged, "
        "or it may not be an Aegis vault."
    )


class UnlockError(AegisError):
    """Base class for failures to open a vault with a credential."""

    user_message = "That doesn't open this vault. Check it and try again."


class WrongPasswordError(UnlockError):
    """The password given does not open this vault."""

    user_message = (
        "That password doesn't open this vault. Check it and try again."
    )


class WrongRecoveryKeyError(UnlockError):
    """The recovery key given does not open this vault."""

    user_message = (
        "That recovery key doesn't open this vault. "
        "Check it carefully and try again."
    )


class VaultTamperedError(AegisError):
    """The vault opened, but its contents fail their checks."""

    user_message = (
        "This vault's contents don't check out — the file has been "
        "changed or damaged, so Aegis won't open it."
    )


class VaultLockedError(AegisError):
    """An operation was attempted on a locked vault session."""

    user_message = "This vault is locked. Open it again to use it."


class WeakPasswordError(AegisError):
    """A new master password is too short to accept."""

    user_message = (
        "That password is too short. Use at least 8 characters — "
        "a short phrase you can remember works well."
    )


class VaultExistsError(AegisError):
    """A vault already exists at the requested location."""

    user_message = (
        "There's already a vault at that spot. "
        "Pick a different name or place."
    )


class VaultSaveError(AegisError):
    """A save (or the publish step of creating a vault) failed."""

    user_message = (
        "Aegis couldn't save this vault. Make sure there's room on "
        "the drive and the file isn't open somewhere else, then try again."
    )


class VaultChangedOnDiskError(AegisError):
    """The vault file changed on disk after this session opened it."""

    user_message = (
        "This vault changed on disk after you opened it, so Aegis "
        "didn't save over it. Close it and open it again to see the "
        "newest copy."
    )


class CredentialNotFoundError(AegisError):
    """The named saved login is not in the vault."""

    user_message = "That login isn't saved in this vault."


class InvalidCredentialError(AegisError, ValueError):
    """A saved login's details cannot be accepted."""

    user_message = (
        "That login can't be saved. Check the details and try again — "
        "every login needs a name for the site or app it belongs to."
    )


class PasswordStoreDamagedError(AegisError):
    """The saved-logins list inside a vault fails its checks."""

    user_message = (
        "This vault's saved logins don't check out — they have been "
        "changed or damaged, so Aegis won't use them. Your files in "
        "this vault are not affected."
    )


class EntryNotFoundError(AegisError):
    """The named item is not in the vault."""

    user_message = "That item isn't in this vault."


class InvalidEntryNameError(AegisError, ValueError):
    """An item name cannot be used inside a vault."""

    user_message = (
        "That name can't be used in a vault. "
        "Keep it a simple file or folder name."
    )


# -- Phase 3: the Strongbox ---------------------------------------------------


class InvalidStrongboxEntryError(AegisError, ValueError):
    """An item cannot be saved in the Strongbox as given."""

    user_message = (
        "That item can't be saved in the Strongbox. "
        "Check the details and try again."
    )


class StrongboxNotFoundError(AegisError):
    """The named item is not in the Strongbox."""

    user_message = "That item isn't in the Strongbox."


class StrongboxDamagedError(AegisError):
    """The Strongbox list inside a vault fails its checks."""

    user_message = (
        "This vault's Strongbox doesn't check out — it has been "
        "changed or damaged, so Aegis won't use it. Your other "
        "items in this vault are not affected."
    )


class DocumentTooLargeError(AegisError):
    """A document copy is bigger than the Strongbox holds."""

    user_message = (
        "That document is too big for the Strongbox — it holds "
        "copies up to 10 MB each. For a bigger file, keep the "
        "file itself in the vault instead."
    )


# -- Phase 3: standalone sealed files (Lock-and-send, Lazarus's armor) --------


class WrongFilePasswordError(UnlockError):
    """The password given does not open this sealed file."""

    user_message = (
        "That password doesn't open this file. Check it and try again."
    )


class SealedFormatError(AegisError):
    """The file is not a standalone sealed file this copy can open."""

    user_message = (
        "This file isn't a sealed file Aegis can open — it may be "
        "damaged, or it may not be an Aegis sealed file."
    )


class SealedTamperedError(AegisError):
    """A sealed file opened, but its contents fail their checks."""

    user_message = (
        "This file's contents don't check out — it has been "
        "changed or damaged, so Aegis won't open it."
    )


class SealedExistsError(AegisError):
    """Something already exists where a sealed file would be written."""

    user_message = (
        "There's already something at that spot. Pick a different "
        "name or place, or move what's there first."
    )


class SealedSaveError(AegisError):
    """Writing a sealed file (or what it opens into) failed."""

    user_message = (
        "Aegis couldn't write that file. Make sure there's room "
        "on the drive and the file isn't open somewhere else, "
        "then try again."
    )


class SealedSourceError(AegisError):
    """What was asked to be sealed cannot be sealed as given."""

    user_message = "That can't be sealed. Check it and try again."


class ArmorRefusalError(AegisError):
    """A folder cannot be sealed into an armored set as it stands."""

    user_message = (
        "Aegis can't seal that folder as it is. "
        "Check it and try again."
    )
