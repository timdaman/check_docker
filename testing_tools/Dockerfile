ARG tag
FROM python:$tag
RUN apk --no-cache add bash
COPY dev_requirements.txt /
RUN pip install -r /dev_requirements.txt
ENTRYPOINT [ "py.test" ]