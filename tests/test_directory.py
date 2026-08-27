from session_assist.services.directory import computer_filter, escape_filter_value, realm_to_base_dn


def test_realm_derives_standard_active_directory_base_dn():
    assert realm_to_base_dn("EXAMPLE.ORG") == "DC=EXAMPLE,DC=ORG"


def test_directory_filter_escapes_user_text():
    query = r"room*)(|(name=*)"
    escaped = escape_filter_value(query)
    assert escaped == r"room\2a\29\28|\28name=\2a\29"
    search_filter = computer_filter(query)
    assert "(objectCategory=computer)" in search_filter
    assert "room\\2a\\29\\28|\\28name=\\2a\\29" in search_filter


def test_empty_query_does_not_request_all_computers():
    assert computer_filter("") == "(objectCategory=computer)"
