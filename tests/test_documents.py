from app.documents import guess_doc_type


def test_guesses_core_packet():
    assert guess_doc_type("cms1500.txt", "CMS-1500 Claim Form") == "claim_form"
    assert guess_doc_type("invoice.txt", "Itemized bill $158.00") == "itemized_bill"
    assert guess_doc_type("op_note.txt", "Operative note") == "medical_record"
    assert guess_doc_type("lab.txt", "Lab report") == "medical_record"
    assert guess_doc_type("card.txt", "Member identification card") == "id_document"
