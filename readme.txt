----- readme -----

index.txt: 내용 수정
사이트 제목: cryptoencode로 변경

@after_this_request 추가 
- 사용자 파일에 대한 삭제 처리 추가


analyzer-pem.html
    - required 처리, 라운드 버튼
    - segment 처리

analyzer-file.html
    - file --> required  속성 추가
    - 라운드 버튼
    - - segment 처리

analyser-pkcs12.html
    - 예외처리
    - 파일 삭제
    - required
    - round btn
    - segment 처리

cipher_encrypt:
    - input password/output password : required 속성 추가
    - 암호 일치 여부 확인 : 스크립트 추가
    - input file : 필수 입력 처리
    - exception : run_command에 대한 예외 처리 추가
    - @after_this_request 추가 
    - segment 처리

cipher-pubkey_encrypt.html
    - segment=segment
    - 예외
    - 라운드 버튼

generator-base64
    - 설명 
    - 예외
    - 라운드
    - 세그먼트
    - req
    - errmsg XXXX


===== ref
@after_this_request
            def remove_file(response):
                try:
                    os.remove(outfile)
                    app.logger.info("Remove: %s" % outfile)
                    os.remove(infile)
                    app.logger.info("Remove: %s" % infile)
                except Exception as error:
                    app.logger.error("Error Removing or closing downloaded file", error)
                return response

