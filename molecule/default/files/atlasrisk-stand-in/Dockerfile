# Molecule only: stands in for AtlasRisk's API and risk-worker images until
# Molecule can pull a real release. Same command line, same non-root user.
FROM python:3.14.7-slim-trixie@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY stand_in.py /stand_in.py
USER 65532:65532
ENTRYPOINT ["python3", "/stand_in.py"]
