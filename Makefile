.PHONY: install run detect test lint report dashboard clean

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

dashboard:
	absolutus dashboard

clean:
	rm -f data/events.csv data/absolutus.db r/analysis.html
