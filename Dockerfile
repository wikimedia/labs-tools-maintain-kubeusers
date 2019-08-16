FROM alpine:3.10.1

# Be conservative, and do not include things that are language specific!
RUN apk add --no-cache --virtual .fetch-deps \
    libffi-dev openssl-dev python3 python3-dev musl-dev gcc ca-certificates

WORKDIR /app

COPY maintain_kubeusers/maintain_kubeusers.py .
COPY requirements.txt .

RUN python3 -m venv venv

RUN source venv/bin/activate

RUN venv/bin/pip install -r requirements.txt

CMD ["venv/bin/python", "maintain_kubeusers.py" , "--once", "--debug"]
