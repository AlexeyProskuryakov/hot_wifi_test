FROM golang

ADD . /go/src/github.com/alexeyproskuryakov/hot_wifi_test

WORKDIR /go/src/github.com/alexeyproskuryakov/hot_wifi_test
RUN go get -d ./...
RUN go install github.com/alexeyproskuryakov/hot_wifi_test

ENTRYPOINT /go/bin/hot_wifi_test

EXPOSE 8080