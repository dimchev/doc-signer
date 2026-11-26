"""Generates the encrypted PDF fixtures in tests/fixtures/encrypted (needs pikepdf)."""
import pathlib
import pikepdf

root = pathlib.Path(__file__).resolve().parent.parent / "tests" / "fixtures"
out = root / "encrypted"
out.mkdir(exist_ok=True)
deny = pikepdf.Permissions(modify_annotation=False, modify_form=False, modify_other=False, modify_assembly=False)
cases = {
    # name: (R, aes, user password, permissions)
    "rc4-40-owner.pdf": (2, False, "", pikepdf.Permissions()),
    "rc4-128-user.pdf": (3, False, "user", pikepdf.Permissions()),
    "aes-128-owner.pdf": (4, True, "", pikepdf.Permissions()),
    "aes-256-user.pdf": (6, True, "user", pikepdf.Permissions()),
    "aes-256-no-signing.pdf": (6, True, "", deny),
}
for name, (r, aes, user, allow) in cases.items():
    with pikepdf.open(root / "minimal.pdf") as pdf:
        pdf.docinfo["/Title"] = "Encrypted fixture " + name
        pdf.save(out / name, encryption=pikepdf.Encryption(owner="owner", user=user, R=r, aes=aes, allow=allow, metadata=r >= 4))
    print(name, (out / name).stat().st_size)
