from pipeline.clean import ascii_fold, clean_text, is_english, norm_key
from app.services import url_checker


def test_language_filter():
    assert is_english("Your account has been suspended. Please verify your details to restore access.")
    assert is_english("Ok see you at the station in ten minutes")
    assert not is_english("Voce alcancou o cartao Black, mas ha algo que voce nao pode perder para os seus clientes")
    assert not is_english("Herzlichen Glueckwunsch, Sie sind einer der Finalisten fuer unser Gewinnspiel und wir gratulieren Ihnen")
    assert not is_english("\u7701\u6797\u529e\u7ed9\u6211\u53d1\u4e0a\u79d1\u5927\u5f55\u53d6\u77ed\u4fe1")


def test_clean_removes_source_artifacts_and_pii():
    raw = ("Re: [Exmh-workers] Hello\n\nDear phishing@pot,\nCall me on +91 98765 43210 or mail bob@corp.com\n"
           "> quoted reply line\nJohn wrote:\n_______________________________________________\n"
           "Exmh-workers mailing list\nSee https://example.org/a deathtospamdeathtospam\n-- \nSignature")
    out = clean_text(raw, "email")
    assert out.startswith("Hello")                        # subject prefixes/list tags stripped
    assert "phishing@pot" not in out and "bob@corp.com" not in out and "98765" not in out
    assert "quoted reply" not in out and "mailing list" not in out.lower() and "deathtospam" not in out.lower()
    assert "Signature" not in out and "https://example.org/a" in out


def test_long_random_tokens_and_padding_removed():
    junk = "A" * 5 + "9" * 40 + "xYz"
    out = clean_text("Win big now\n\n" + junk + "\n" + "\n" * 50 + "Claim at http://x.top/a", "email")
    assert junk not in out and "\n\n\n" not in out and "Claim at http://x.top/a" in out


def test_ascii_fold_and_dedup_key():
    assert ascii_fold("caf\u00e9 \u2714 ok") == "cafe  ok".replace("  ", " ")
    assert norm_key("Pay 500 now http://a.com/x") == norm_key("pay 750 NOW http://b.org/y")


def test_blocklist_feed_loaded_but_shared_hosts_never_blocked():
    bl = url_checker.load_blocklist()
    assert len(bl) > 1000                                  # live feed present
    assert "sites.google.com" not in bl and "netlify.app" not in bl
    assert "paypa1-secure-login.com" in bl                 # hand-kept demo entry
