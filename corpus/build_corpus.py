"""Author-owned synthetic scenario corpus. No real people or messages."""
import json
from pathlib import Path
from email.message import EmailMessage
ROOT=Path(__file__).resolve().parent
# Families, not spelling variants, are split as one unit by baseline.py.
SCENARIOS=[
('p01','phishing','Account validation','Verify your password immediately or your account will be suspended. Confirm your password at the support portal.','credentials'),
('p02','phishing','Parcel customs charge','Your parcel is held. Pay a processing fee within 2 hours and provide bank details to release it.','payment'),
('p03','phishing','Payroll bank update','Urgent payroll update. Send your bank details and confirm your login credentials before salary processing.','credentials'),
('p04','phishing','Shared document requires sign in','A confidential file is waiting. Enter your password to open the shared document. Access expires today.','masked'),
('p05','phishing','Gift card request from director','I am in a meeting. Buy gift cards immediately and send the codes. Keep this confidential.','reply'),
('p06','phishing','Tax refund available','Claim your refund. Provide bank details and pay a release fee within 4 hours.','payment'),
('p07','phishing','Email storage full','Your mailbox will be blocked. Verify your password to upgrade storage immediately.','masked'),
('p08','phishing','Prize claim notice','Congratulations on your prize. Send a processing fee by wire transfer to receive your reward.','payment'),
('p09','phishing','MFA support verification','Support needs to verify your identity. Share your OTP immediately to prevent account suspension.','credentials'),
('p10','phishing','Invoice attachment','Urgent invoice attached. Enable active content to review the overdue payment document.','attachment'),
('p11','phishing','Scholarship acceptance charge','Your scholarship is approved. Pay the release fee using cryptocurrency before this last chance expires.','payment'),
('p12','phishing','HR contract signature','Open your contract now. Enter your login credentials in the verification portal to avoid losing your role.','masked'),
('p13','phishing','Bank transfer rejected','Account blocked. Update your bank details and enter your passcode to restore payments.','credentials'),
('p14','phishing','Delivery address correction','Confirm your address and pay a processing fee for delivery today. Final warning for your parcel.','ip'),
('p15','phishing','Security incident action','Someone logged in. Reset your password at this recovery page immediately to prevent closure.','masked'),
('p16','phishing','New voicemail recording','Your voice message is waiting. Open the attached player to hear the recording.','attachment'),
('p17','phishing','Vendor bank replacement','We changed our bank account. Transfer funds immediately to the new account and reply for instructions.','reply'),
('p18','phishing','Course registration hold','Verify your password to confirm your course place. Pay a processing fee within 3 hours.','credentials'),
('p19','phishing','Friend needs help','I lost my wallet while travelling. Please send a wire transfer urgently and reply to this new address.','reply'),
('p20','phishing','Payment receipt ready','Your receipt is available. View the document in the portal to see the details.','masked'),
('b01','benign','Seminar room booking','Your seminar room booking is confirmed for Thursday. Bring your student card to reception.','plain'),
('b02','benign','Password reset requested','You requested a password reset. Open the official app to continue. Never share your password or one-time code.','plain'),
('b03','benign','Project meeting notes','Attached are the project meeting notes. Please review the schedule before our discussion next week.','document'),
('b04','benign','Library renewal receipt','Your books were renewed. The next due date is shown in your library account. Thank you for using the library.','plain'),
('b05','benign','Invoice from regular supplier','Here is the invoice for the order agreed last week. Payment is due next month using our existing account details.','document'),
('b06','benign','Security awareness workshop','Join our workshop about phishing. We will discuss gift cards, suspicious links, and why you must never share your OTP.','plain'),
('b07','benign','Lab equipment ready','Your reserved equipment is ready for collection. Check the inventory with the technician before taking it.','plain'),
('b08','benign','Subscription newsletter','This month we share reading recommendations and upcoming community events. You can manage your subscription on our website.','link'),
('b09','benign','Support ticket response','Thank you for reporting the display problem. Please reply with your application version and a description of what happened.','reply'),
('b10','benign','Exam timetable published','The examination timetable is now available. Visit the official student portal using your saved bookmark.','plain'),
('b11','benign','Travel expense receipt','Your expense reimbursement has been processed. No further action is required. Contact finance through the directory for questions.','plain'),
('b12','benign','Club volunteer rota','The volunteer rota is attached. Let the coordinator know if you need to swap a shift.','document'),
('b13','benign','Urgent room closure','Urgent notice: the laboratory is closed immediately due to a water leak. Meet in the adjacent teaching room.','plain'),
('b14','benign','Account sign-in notice','A new sign in was detected on your account. If this was you, no action is needed. Otherwise open the official app directly.','plain'),
('b15','benign','Donation event invitation','Our community event supports the food bank. Donations are optional. See the programme at our website.','link'),
('b16','benign','Research feedback','Thank you for sharing your draft. I added comments about your method and conclusion. We can discuss them next week.','document'),
('b17','benign','Conference registration','Your registration is complete. Keep the confirmation for entry. The programme and directions are on our website.','link'),
('b18','benign','Scheduled maintenance','The student portal will be unavailable overnight for maintenance. Your files will remain available afterward.','plain'),
('b19','benign','Training payment example','For this accounting exercise, calculate a wire transfer processing fee. Do not send money. Bring your answer to the tutorial.','plain'),
('b20','benign','Document review reminder','Please read the document in our shared workspace before Friday. The link points to the usual team host.','link')]
manifest=[]
for family,label,subject,body,kind in SCENARIOS:
    for v in range(4):
        m=EmailMessage(); sender='office.example.org'
        m['From']='Campus services <notice@'+sender+'>'; m['To']='Student <student@example.net>'
        m['Subject']=subject+['',' — reminder',' — notice',' — information'][v]
        m['Date']=f'Mon, 19 Oct 2026 {8+v:02d}:00:00 +0800'; m['Message-ID']=f'<{family}-{v}@fixtures.example.org>'
        if kind=='reply': m['Reply-To']='help@different.example.net'
        m.set_content(['Hello,','Dear student,','Good morning,','Hello team,'][v]+'\n\n'+body+'\n\n'+['Regards,\nService team','Thank you,\nOffice','Best wishes,\nCoordinator','Service desk'][v])
        if kind in ('masked','credentials','payment','ip'):
            target='http://192.0.2.55/verify' if kind=='ip' else 'https://review.example.net/continue'
            m.add_alternative('<html><body><p>'+body+'</p><a href="'+target+'">https://portal.example.org/account</a></body></html>',subtype='html')
        if kind=='link': m.add_alternative('<p>'+body+'</p><a href="https://office.example.org/info">https://office.example.org/info</a>',subtype='html')
        if kind in ('attachment','document'):
            m.add_attachment(b'Synthetic inert attachment. No executable content.',maintype='application',subtype='octet-stream',filename='invoice.docm' if kind=='attachment' else 'notes.txt')
        file=f'{family}-{v}.eml'; (ROOT/file).write_bytes(m.as_bytes())
        manifest.append({'id':family+'-'+str(v),'family':family,'label':label,'file':file,'provenance':'Locally authored synthetic scenario; no real email; author-assigned intent label','scenario':subject})
(ROOT/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('Wrote',len(manifest),'synthetic messages from',len(SCENARIOS),'families')
