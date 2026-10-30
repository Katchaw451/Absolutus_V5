.PHONY: install run detect test lint report clean

install:
	pip install -e .

run:
	absolutus parse

detect:
	absolutus detect top

test:
	python3 -m unittest discover -s tests -v

lint:
	ruff check .

report:
	absolutus report

clean:
	rm -f data/events.csv data/absolutus.db r/analysis.html
